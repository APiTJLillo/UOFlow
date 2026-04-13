#pragma once

#include <cstdint>

namespace Engine::Addresses {

constexpr std::uint32_t RVA_BuildAction = 0x0013E630;
constexpr std::uint32_t RVA_EnqueueAction = 0x00160BD0;
constexpr std::uint32_t RVA_Vtbl_CastSpell = 0x001C9C5C;
constexpr std::uint32_t RVA_ActionFactoryLookup = 0x001648F0;
constexpr std::uint32_t RVA_ActionPostWakeA = 0x00075460;
constexpr std::uint32_t RVA_ActionPostWakeB = 0x00076020;
constexpr std::uint32_t CAST_OFS_TargetType = 0x4;
constexpr std::uint32_t CAST_OFS_SpellId = 0x8;
constexpr std::uint32_t CAST_OFS_IconId = 0xC;
constexpr std::uint32_t CAST_OFS_TargetId = 0x10;
constexpr std::uint32_t CAST_OFS_TargetReadyFlag = 0x18;

} // namespace Engine::Addresses
