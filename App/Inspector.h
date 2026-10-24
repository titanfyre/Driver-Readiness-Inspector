#pragma once
#include "ThirdParty/json.hpp"
#include <cstdint>
#include <atomic>
#include <string>
#include <vector>

namespace Inspector {
using Json = nlohmann::json;
struct Options { bool include_sensitive = false; bool events = false; std::atomic_bool* stop = nullptr; };
Json Collect(const Options& options);
Json Preview();
Json Value(std::string status, Json value, std::uint32_t error = 0, std::string detail = {});
Json DecodeRegistryValue(std::uint32_t type, const std::vector<std::uint8_t>& bytes);
// Pure syntax policy for normalized drive-absolute binary paths; performs no I/O.
bool LocalBinaryPathSyntax(const std::wstring& path) noexcept;
Json BinaryEvidence(const std::wstring& path);
std::string HtmlEscape(const std::string& text);
std::string Html(const Json& report);
std::string Summary(const Json& report);
std::string DeviceSummary(const Json& device);
std::string ServiceSummary(const Json& service);
std::string Problem(std::uint32_t code);
std::string JsonText(const Json& report);
bool WriteReport(const std::wstring& path, const std::string& bytes, std::string& error);
bool SelfTest(std::string& result);
}
