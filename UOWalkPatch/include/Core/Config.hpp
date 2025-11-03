#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace Core::Config {

    enum class LookupSource {
        None,
        Environment,
        ConfigFile
    };

    struct LookupResult {
        LookupSource source = LookupSource::None;
        std::string  value;
    };

    void EnsureLoaded();

    std::optional<std::string> TryGetValue(const std::string& key, LookupResult* outMeta = nullptr);
    std::optional<std::string> TryGetEnv(const std::string& name, LookupResult* outMeta = nullptr);

    std::optional<bool> TryGetBool(const std::string& key, LookupResult* outMeta = nullptr);
    std::optional<bool> TryGetEnvBool(const std::string& name, LookupResult* outMeta = nullptr);

    std::optional<int> TryGetInt(const std::string& key, LookupResult* outMeta = nullptr);
    std::optional<unsigned> TryGetUInt(const std::string& key, LookupResult* outMeta = nullptr);
    std::optional<uint32_t> TryGetMilliseconds(const std::string& key, LookupResult* outMeta = nullptr);

    uint32_t GetSendBuilderSettleTimeoutMs();
    bool SendBuilderAllowCallsitePivot();
    bool SendBuilderAllowDbMgrPivot();
    uint32_t HelpersPostAckTimeoutMs();
    bool HelpersAllowApcFallback();
    bool HelpersAllowRemoteThreadFallback();
    bool HelpersIgnoreGlobalSettleIfSbReady();

    std::optional<std::string> GetLoggingLevel();
    std::optional<uint32_t> GetLoggingBurstDebugMs();
    std::optional<uint32_t> GetLoggingDebounceMs();
    std::optional<std::string> GetLoggingCategories();

    std::string ConfigSourcePath();

} // namespace Core::Config
