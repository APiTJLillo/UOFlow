#pragma once

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <string>
#include <optional>

namespace uow {

struct SendEndpoint {
    using Fn = void(__thiscall*)(void* mgr, const void* buf, int len);
    Fn fn = nullptr;
    void* mgr = nullptr;
};

struct RegionInfo {
    MEMORY_BASIC_INFORMATION mbi{};
    bool is_exec = false;
    bool is_committed = false;
    bool good() const { return is_exec && is_committed; }
};

inline RegionInfo query_region(void* p) {
    RegionInfo r;
    if (VirtualQuery(p, &r.mbi, sizeof(r.mbi)) == sizeof(r.mbi)) {
        r.is_committed = (r.mbi.State == MEM_COMMIT);
        const auto prot = r.mbi.Protect & 0xFF;
        r.is_exec = (prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
                     prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
    }
    return r;
}

class TailFollowScanner {
public:
    TailFollowScanner(void* maybeNetMgr, void** maybeVtbl, std::size_t vtblSlotsHint)
        : m_maybeNetMgr(maybeNetMgr), m_maybeVtbl(maybeVtbl), m_vtblSlotsHint(vtblSlotsHint) {}

    void update_anchors(void* maybeNetMgr, void** maybeVtbl, std::size_t vtblSlotsHint) {
        m_maybeNetMgr = maybeNetMgr;
        m_maybeVtbl = maybeVtbl;
        if (vtblSlotsHint)
            m_vtblSlotsHint = vtblSlotsHint;
    }

    std::optional<SendEndpoint> resolve_best() {
        if (auto ep = try_vtbl_paths())
            return ep;
        if (auto ep = try_tail_follow())
            return ep;
        return std::nullopt;
    }

    void note_tail(void* fn) {
        m_tailSeen.store(reinterpret_cast<SendEndpoint::Fn>(fn), std::memory_order_release);
    }

private:
    std::optional<SendEndpoint> try_vtbl_paths() {
        if (!m_maybeVtbl || !*m_maybeVtbl)
            return std::nullopt;

        const std::size_t scanSlots = m_vtblSlotsHint ? (m_vtblSlotsHint + 8) : 64;
        auto** vtbl = reinterpret_cast<void**>(m_maybeVtbl);
        for (std::size_t i = 0; i < scanSlots; ++i) {
            auto pfn = reinterpret_cast<SendEndpoint::Fn>(vtbl[i]);
            if (!pfn)
                continue;
            if (!guard_endpoint(pfn))
                continue;
            return SendEndpoint{pfn, m_maybeNetMgr};
        }
        return std::nullopt;
    }

    std::optional<SendEndpoint> try_tail_follow() {
        auto pfn = m_tailSeen.exchange(nullptr, std::memory_order_acq_rel);
        if (!pfn)
            return std::nullopt;
        if (!guard_endpoint(pfn))
            return std::nullopt;
        return SendEndpoint{pfn, m_maybeNetMgr};
    }

    bool guard_endpoint(SendEndpoint::Fn fn) const {
        auto region = query_region(reinterpret_cast<void*>(fn));
        if (!region.good())
            return false;

        const std::uint8_t* bytes = reinterpret_cast<const std::uint8_t*>(fn);
        __try {
            std::uint8_t b0 = bytes[0];
            if (!(b0 == 0x40 || b0 == 0x48 || b0 == 0x55))
                return false;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        if (m_maybeNetMgr) {
            void** vtbl = *reinterpret_cast<void***>(m_maybeNetMgr);
            if (!vtbl)
                return false;
            RegionInfo rv = query_region(vtbl);
            if (!rv.is_committed)
                return false;
        }
        return true;
    }

private:
    void*  m_maybeNetMgr = nullptr;
    void** m_maybeVtbl = nullptr;
    std::size_t m_vtblSlotsHint = 0;
    std::atomic<SendEndpoint::Fn> m_tailSeen{nullptr};
};

} // namespace uow

