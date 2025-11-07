#pragma once

#include <cstdint>

namespace CastCorrelator {

constexpr unsigned short kMaxRecordedFrames = 16;

struct SendEvent {
    const char* apiTag = nullptr;
    const char* buffer = nullptr;
    int length = 0;
    unsigned char packetId = 0;
    uint32_t tick = 0;
    bool targetFilterArmed = false;
    void* frames[kMaxRecordedFrames]{};
    unsigned short frameCount = 0;
};

void Init();
void Shutdown();
bool IsEnabled();
bool ShouldCaptureStack(unsigned char packetId);
void OnCastAttempt(uint32_t spellId);
void OnSendEvent(const SendEvent& ev);

} // namespace CastCorrelator
