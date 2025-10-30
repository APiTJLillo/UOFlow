#pragma once

namespace Core::StartupSummary {
    void Initialize(bool movementHooksOk,
                    bool packetTraceOk,
                    bool sendBuilderOk,
                    bool luaBridgeOk);
    void NotifyHelpersReady();
    void NotifyEngineContextReady();
    void NotifyLuaHeartbeat();
    void NotifySendBuilderReady();
}
