#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

struct TargetCorrelator {
    bool armed = false;
    uint64_t t0 = 0;
    uint32_t windowMs = 600;
    bool enabled = false;
    bool verbose = false;
    uintptr_t frameHint = 0;
    bool hintAnnounced = false;
    uint32_t seq = 0;
    char reason[64]{};

    void Arm(const char* why = nullptr);
    void Disarm(const char* why = nullptr);
    bool ShouldCaptureStack(std::uint8_t packetId) const;
    std::optional<uint64_t> TagIfWithin(std::uint8_t packetId, std::size_t len, void* topFrame);
};

extern TargetCorrelator g_targetCorr;

void TargetCorrelatorInit();
void TargetCorrelatorShutdown();
bool TargetCorrelatorEnabled();
