#include "Core/Config.hpp"

#include <windows.h>

#include <algorithm>
#include <charconv>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace Core::Config {
namespace {

struct State {
    bool loaded = false;
    std::unordered_map<std::string, std::string> values;
    std::string sourcePath;
};

std::once_flag g_loadOnce;
State g_state;

std::string Trim(const std::string& input) {
    size_t begin = 0;
    size_t end = input.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(input[begin])))
        ++begin;
    while (end > begin && std::isspace(static_cast<unsigned char>(input[end - 1])))
        --end;
    return input.substr(begin, end - begin);
}

std::string StripInlineComment(const std::string& line) {
    size_t commentPos = std::string::npos;
    for (char marker : {'#', ';'}) {
        size_t pos = line.find(marker);
        if (pos != std::string::npos && (commentPos == std::string::npos || pos < commentPos))
            commentPos = pos;
    }
    if (commentPos != std::string::npos)
        return line.substr(0, commentPos);
    return line;
}

std::string ToUpperAscii(std::string value) {
    for (char& ch : value)
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    return value;
}

bool InterpretBool(const std::string& text, bool& outValue) {
    std::string trimmed = Trim(text);
    if (!trimmed.empty() && (trimmed.front() == '"' || trimmed.front() == '\'')) {
        trimmed.erase(trimmed.begin());
        trimmed = Trim(trimmed);
    }
    if (trimmed.empty()) {
        outValue = false;
        return true;
    }
    switch (trimmed.front()) {
        case '0':
        case 'n':
        case 'N':
        case 'f':
        case 'F':
            outValue = false;
            break;
        default:
            outValue = true;
            break;
    }
    return true;
}

void LoadConfig() {
    g_state.loaded = true;

    char modulePath[MAX_PATH] = {};
    if (GetModuleFileNameA(reinterpret_cast<HMODULE>(&__ImageBase), modulePath, ARRAYSIZE(modulePath)) == 0)
        return;

    std::string basePath(modulePath);
    size_t slash = basePath.find_last_of("\\/");
    if (slash != std::string::npos)
        basePath.resize(slash + 1);
    else
        basePath.clear();

    if (basePath.empty())
        return;

    std::vector<std::string> searchDirs;
    std::string current = basePath;
    for (int i = 0; i < 4 && !current.empty(); ++i) {
        if (std::find(searchDirs.begin(), searchDirs.end(), current) == searchDirs.end())
            searchDirs.push_back(current);
        std::string parent = current;
        if (!parent.empty() && (parent.back() == '\\' || parent.back() == '/'))
            parent.pop_back();
        size_t parentSlash = parent.find_last_of("\\/");
        if (parentSlash == std::string::npos)
            break;
        parent.resize(parentSlash + 1);
        if (parent.empty() || parent == current)
            break;
        current = parent;
    }

    const char* candidates[] = {"uowalkpatch.cfg", "uowalkpatch.ini"};
    for (auto dirIt = searchDirs.rbegin(); dirIt != searchDirs.rend(); ++dirIt) {
        for (const char* name : candidates) {
            std::string fullPath = *dirIt + name;
            std::ifstream stream(fullPath);
            if (!stream.is_open())
                continue;

            g_state.sourcePath = fullPath;
            std::string line;
            while (std::getline(stream, line)) {
                std::string stripped = StripInlineComment(line);
                std::string cleaned = Trim(stripped);
                if (cleaned.empty())
                    continue;
                size_t eq = cleaned.find('=');
                if (eq == std::string::npos)
                    continue;
                std::string key = Trim(cleaned.substr(0, eq));
                std::string value = Trim(cleaned.substr(eq + 1));
                if (key.empty())
                    continue;
                g_state.values[ToUpperAscii(key)] = value;
            }
        }
    }
}

std::optional<std::string> GetEnvVar(const std::string& name) {
    if (name.empty())
        return std::nullopt;
    DWORD required = GetEnvironmentVariableA(name.c_str(), nullptr, 0);
    if (required == 0)
        return std::nullopt;
    std::string buffer(static_cast<size_t>(required), '\0');
    DWORD written = GetEnvironmentVariableA(name.c_str(), buffer.data(), required);
    if (written == 0 && GetLastError() != ERROR_SUCCESS)
        return std::nullopt;
    buffer.resize(static_cast<size_t>(written));
    return buffer;
}

bool StrToInt64(const std::string& text, int64_t& outValue) {
    std::string trimmed = Trim(text);
    if (trimmed.empty())
        return false;

    const char* begin = trimmed.data();
    const char* end = begin + trimmed.size();
    int64_t value = 0;
    auto result = std::from_chars(begin, end, value, 10);
    if (result.ec != std::errc() || result.ptr != end)
        return false;

    outValue = value;
    return true;
}

} // namespace

void EnsureLoaded() {
    std::call_once(g_loadOnce, LoadConfig);
}

std::optional<std::string> TryGetValue(const std::string& key, LookupResult* outMeta) {
    EnsureLoaded();
    if (key.empty())
        return std::nullopt;
    std::string upper = ToUpperAscii(key);
    auto it = g_state.values.find(upper);
    if (it == g_state.values.end())
        return std::nullopt;
    if (outMeta) {
        outMeta->source = LookupSource::ConfigFile;
        outMeta->value = it->second;
    }
    return it->second;
}

std::optional<std::string> TryGetEnv(const std::string& name, LookupResult* outMeta) {
    auto value = GetEnvVar(name);
    if (value && outMeta) {
        outMeta->source = LookupSource::Environment;
        outMeta->value = *value;
    }
    return value;
}

std::optional<bool> TryGetBool(const std::string& key, LookupResult* outMeta) {
    auto value = TryGetValue(key, outMeta);
    if (!value)
        return std::nullopt;
    bool parsed = false;
    if (!InterpretBool(*value, parsed))
        return std::nullopt;
    return parsed;
}

std::optional<bool> TryGetEnvBool(const std::string& name, LookupResult* outMeta) {
    auto value = TryGetEnv(name, outMeta);
    if (!value)
        return std::nullopt;
    bool parsed = false;
    if (!InterpretBool(*value, parsed))
        return std::nullopt;
    return parsed;
}

std::optional<int> TryGetInt(const std::string& key, LookupResult* outMeta) {
    auto value = TryGetValue(key, outMeta);
    if (!value)
        return std::nullopt;
    int64_t parsed = 0;
    if (!StrToInt64(*value, parsed))
        return std::nullopt;
    if (parsed < INT_MIN || parsed > INT_MAX)
        return std::nullopt;
    return static_cast<int>(parsed);
}

std::optional<unsigned> TryGetUInt(const std::string& key, LookupResult* outMeta) {
    auto value = TryGetInt(key, outMeta);
    if (!value || *value < 0)
        return std::nullopt;
    return static_cast<unsigned>(*value);
}

std::optional<uint32_t> TryGetMilliseconds(const std::string& key, LookupResult* outMeta) {
    auto value = TryGetUInt(key, outMeta);
    if (!value)
        return std::nullopt;
    return static_cast<uint32_t>(*value);
}

std::string ConfigSourcePath() {
    EnsureLoaded();
    return g_state.sourcePath;
}

} // namespace Core::Config
