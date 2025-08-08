#include "Core/MinHookHelpers.hpp"

namespace Core {
namespace MinHookHelpers {

bool Init() {
    return MH_Initialize() == MH_OK;
}

void Shutdown() {
    MH_Uninitialize();
}

} // namespace MinHookHelpers
} // namespace Core
