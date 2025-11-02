#pragma once

#include <windows.h>
#include <cstdint>

namespace uow::netcfg {

struct GlobalStateInfo {
    void* lua = nullptr;
    void* dbMgr = nullptr;
    void* scriptCtx = nullptr;
    void* resourceMgr = nullptr;
    void** networkConfigSlot = nullptr; // pointer TO the pointer in the global struct
};

void OnGlobalStateObserved(const GlobalStateInfo& gsi);
void TickNetworkConfigSettle();
void* GetNetworkConfig(); // stable pointer to use
void SettleTimeoutMs(unsigned ms); // default ~3000-5000
void NotifyFallbackCandidate(void* dbMgr, void* vtbl, void* cfg, const char* sourceTag);

} // namespace uow::netcfg
