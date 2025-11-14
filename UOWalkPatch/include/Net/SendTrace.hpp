#pragma once

#include <cstdint>

namespace Net {

struct SendCallsiteFingerprint {
    void* firstExeFrame = nullptr;
    uint32_t head4 = 0;
    uint16_t len = 0;
    uint32_t stackHash = 0;
};

// Returns true if a fingerprint was recorded for the provided counter.
bool QuerySendFingerprint(unsigned counter, SendCallsiteFingerprint& out, uint32_t* outCount = nullptr);

} // namespace Net
