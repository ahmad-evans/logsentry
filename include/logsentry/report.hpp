#pragma once

#include <ostream>

#include "logsentry/detector.hpp"
#include "logsentry/parser.hpp"

namespace logsentry {

// Formats seconds-since-Jan-1 back into "Nov 23 14:02:11".
std::string format_timestamp(std::int64_t ts);

// Escapes a string for safe inclusion in JSON output.
std::string json_escape(const std::string& s);

void write_text_report(std::ostream& out, const ParseStats& stats, const Detector& detector,
                       std::size_t top_n = 5);
void write_json_report(std::ostream& out, const ParseStats& stats, const Detector& detector);

}  // namespace logsentry
