#include "Net/NetCfgPivot.h"

#include <atomic>
#include <cstdint>

#include "Core/Logging.hpp"
#include "Net/SendBuilder.hpp"

namespace {

std::atomic<void*> g_NetCfg{nullptr};
std::atomic<void*> g_DbMgr{nullptr};
std::atomic<void**> g_NetCfgSlot{nullptr};
std::atomic<bool> g_FallbackTriggered{false};
std::atomic<bool> g_FallbackLogged{false};
DWORD g_SettleStart = 0;
DWORD g_SettleTimeoutMs = 4000;

bool IsReadablePtr(void* p) {
    if (!p)
        return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(p, &mbi, sizeof(mbi)))
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
        return false;
    constexpr DWORD kReadableMask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & kReadableMask) != 0;
}

bool TryUseGlobal() {
    void** slot = g_NetCfgSlot.load(std::memory_order_acquire);
    if (!slot)
        return false;

    void* value = nullptr;
    __try {
        value = *slot;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    if (!value || !IsReadablePtr(value))
        return false;

    void* previous = g_NetCfg.exchange(value, std::memory_order_acq_rel);
    if (previous == value)
        return true;

    Log::Logf(Log::Level::Info,
              Log::Category::Core,
              "[INFO][CORE] [SB] networkConfig adopted from global slot=%p value=%p",
              slot,
              value);

    Net::RegisterNetworkConfigPivot(value, "[GLOBAL]");
    Net::ForceScan(Net::WakeReason::NetCfgSettled);
    g_FallbackLogged.store(true, std::memory_order_release);
    return true;
}

bool TryUseDbMgrFallback() {
    void* db = g_DbMgr.load(std::memory_order_acquire);
    if (!db)
        return false;

    void** vtbl = nullptr;
    __try {
        vtbl = *reinterpret_cast<void***>(db);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    if (!vtbl || !IsReadablePtr(vtbl))
        return false;

    bool firstAttempt = !g_FallbackTriggered.exchange(true, std::memory_order_acq_rel);
    if (firstAttempt) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[INFO][CORE] [SB][ALT] networkConfig fallback request via dbmgr this=%p vtbl=%p",
                  db,
                  vtbl);
    }

    Net::PivotFromDbMgr(db);

    void* current = g_NetCfg.load(std::memory_order_acquire);
    if (!current)
        return false;

    if (!g_FallbackLogged.load(std::memory_order_acquire)) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[INFO][CORE] [SB][ALT] networkConfig fallback via dbmgr this=%p vtbl=%p cfg=%p",
                  db,
                  vtbl,
                  current);
        g_FallbackLogged.store(true, std::memory_order_release);
        Net::RegisterNetworkConfigPivot(current, "[ALT]");
        Net::ForceScan(Net::WakeReason::NetCfgSettled);
    }

    return true;
}

} // namespace

namespace uow::netcfg {

void OnGlobalStateObserved(const GlobalStateInfo& gsi) {
    g_DbMgr.store(gsi.dbMgr, std::memory_order_release);
    g_NetCfgSlot.store(gsi.networkConfigSlot, std::memory_order_release);
    g_SettleStart = GetTickCount();
    g_FallbackTriggered.store(false, std::memory_order_release);
    if (!g_NetCfg.load(std::memory_order_acquire))
        g_FallbackLogged.store(false, std::memory_order_release);

    if (!TryUseGlobal()) {
        TryUseDbMgrFallback();
    }
}

void TickNetworkConfigSettle() {
    if (g_NetCfg.load(std::memory_order_acquire))
        return;
    if (!g_SettleStart)
        return;

    if (TryUseGlobal())
        return;

    DWORD elapsed = GetTickCount() - g_SettleStart;
    if (elapsed >= g_SettleTimeoutMs) {
        TryUseDbMgrFallback();
    }
}

void* GetNetworkConfig() {
    return g_NetCfg.load(std::memory_order_acquire);
}

void SettleTimeoutMs(unsigned ms) {
    g_SettleTimeoutMs = ms ? ms : 4000;
}

void NotifyFallbackCandidate(void* dbMgr, void* vtbl, void* cfg, const char* sourceTag) {
    if (!cfg || !IsReadablePtr(cfg))
        return;

    g_DbMgr.store(dbMgr, std::memory_order_release);
    g_NetCfg.store(cfg, std::memory_order_release);

    if (!g_FallbackLogged.exchange(true, std::memory_order_acq_rel)) {
        Log::Logf(Log::Level::Info,
                  Log::Category::Core,
                  "[INFO][CORE] [SB][ALT] networkConfig fallback via dbmgr this=%p vtbl=%p cfg=%p source=%s",
                  dbMgr,
                  vtbl,
                  cfg,
                  sourceTag ? sourceTag : "(unknown)");
        Net::RegisterNetworkConfigPivot(cfg, sourceTag ? sourceTag : "[ALT]");
        Net::ForceScan(Net::WakeReason::NetCfgSettled);
    }
}

} // namespace uow::netcfg
