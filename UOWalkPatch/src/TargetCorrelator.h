#pragma once

#include <cstdint>

#include "CastCorrelator.h"

namespace TargetCorrelator {

void Init();
void Shutdown();
bool IsEnabled();

void OnRequestTarget();
void OnCursorShown();
void OnCursorHidden();

bool ShouldCaptureStack(unsigned char packetId);
void OnSendEvent(const CastCorrelator::SendEvent& ev);

} // namespace TargetCorrelator
