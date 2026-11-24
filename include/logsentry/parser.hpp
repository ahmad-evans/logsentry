#pragma once

#include <cstdint>
#include <functional>
#include <istream>
#include <optional>
#include <string_view>
#include <vector>

#include "logsentry/event.hpp"

namespace logsentry {

// Parses a syslog timestamp like "Nov 23 14:02:11" into seconds since Jan 1 00:00:00.
// Returns std::nullopt if the text isn't a valid timestamp.
std::optional<std::int64_t> parse_timestamp(std::string_view text);

// Parses one auth.log line. Returns std::nullopt for lines that aren't
// security events we track (cron jobs, session messages, garbage, etc.).
std::optional<AuthEvent> parse_line(std::string_view line, std::size_t line_number = 0);

struct ParseStats {
    std::size_t total_lines = 0;
    std::size_t events = 0;
    std::size_t skipped = 0;  // not an SSH auth event or malformed
};

// Streaming version: calls `on_event` for each event as it's read, so memory use stays flat
// no matter how big the log is. Handles New Year rollover (see parser.cpp).
void parse_stream(std::istream& in, ParseStats& stats, const std::function<void(AuthEvent&&)>& on_event);

// Convenience version that collects every event into a vector (handy for tests).
std::vector<AuthEvent> parse_stream(std::istream& in, ParseStats& stats);

}  // namespace logsentry
