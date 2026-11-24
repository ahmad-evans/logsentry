#include "logsentry/report.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <iomanip>
#include <string>
#include <vector>

namespace logsentry {

std::string format_timestamp(std::int64_t ts) {
    static constexpr std::array<const char*, 12> kMonths = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    // Same 366-day layout as the parser (see parser.cpp)
    static constexpr std::array<int, 13> kDaysBefore = {0,   31,  60,  91,  121, 152, 182,
                                                        213, 244, 274, 305, 335, 366};
    ts %= 366LL * 86400;  // timestamps past New Year carry a year offset; show the calendar date
    int day_of_year = static_cast<int>(ts / 86400);
    int secs = static_cast<int>(ts % 86400);
    std::size_t month = 0;
    while (month < 11 && day_of_year >= kDaysBefore[month + 1]) ++month;
    int day = day_of_year - kDaysBefore[month] + 1;

    char buf[32];
    std::snprintf(buf, sizeof buf, "%s %2d %02d:%02d:%02d", kMonths[month], day, secs / 3600,
                  (secs / 60) % 60, secs % 60);
    return buf;
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

namespace {

int severity_rank(Severity s) {
    switch (s) {
        case Severity::Critical: return 0;
        case Severity::High: return 1;
        case Severity::Medium: return 2;
    }
    return 3;
}

std::vector<Alert> sorted_alerts(const Detector& d) {
    auto alerts = d.alerts();
    std::stable_sort(alerts.begin(), alerts.end(), [](const Alert& a, const Alert& b) {
        return severity_rank(a.severity) < severity_rank(b.severity);
    });
    return alerts;
}

}  // namespace

void write_text_report(std::ostream& out, const ParseStats& stats, const Detector& detector,
                       std::size_t top_n) {
    const auto& ips = detector.ip_stats();
    std::size_t total_fail = 0, total_ok = 0;
    for (const auto& [ip, s] : ips) {
        total_fail += s.failures;
        total_ok += s.successes;
    }

    out << "==================== LogSentry Report ====================\n"
        << "Lines read:        " << stats.total_lines << "\n"
        << "SSH auth events:   " << stats.events << "  (" << stats.skipped << " other lines skipped)\n"
        << "Failed logins:     " << total_fail << "\n"
        << "Successful logins: " << total_ok << "\n"
        << "Unique source IPs: " << ips.size() << "\n\n";

    auto alerts = sorted_alerts(detector);
    out << "ALERTS (" << alerts.size() << ")\n";
    if (alerts.empty()) out << "  none\n";
    for (const auto& a : alerts) {
        out << "  [" << std::left << std::setw(8) << to_string(a.severity) << "] " << std::setw(23)
            << to_string(a.type) << std::setw(16) << a.ip << a.detail << "  (" << format_timestamp(a.first_seen)
            << " -> " << format_timestamp(a.last_seen) << ")\n";
    }

    // Top attacking IPs by failure count
    std::vector<std::pair<std::string, std::size_t>> top;
    for (const auto& [ip, s] : ips) {
        if (s.failures > 0) top.emplace_back(ip, s.failures);
    }
    std::sort(top.begin(), top.end(), [](const auto& a, const auto& b) {
        return a.second != b.second ? a.second > b.second : a.first < b.first;
    });
    if (top.size() > top_n) top.resize(top_n);

    out << "\nTOP SOURCES OF FAILED LOGINS\n";
    for (const auto& [ip, n] : top) {
        out << "  " << std::left << std::setw(16) << ip << std::right << std::setw(6) << n << "\n";
    }
    out << "==========================================================\n";
}

void write_json_report(std::ostream& out, const ParseStats& stats, const Detector& detector) {
    auto alerts = sorted_alerts(detector);
    out << "{\n  \"lines_read\": " << stats.total_lines << ",\n  \"events\": " << stats.events
        << ",\n  \"skipped\": " << stats.skipped << ",\n  \"alerts\": [";
    for (std::size_t i = 0; i < alerts.size(); ++i) {
        const auto& a = alerts[i];
        out << (i ? "," : "") << "\n    {\"type\": \"" << to_string(a.type) << "\", \"severity\": \""
            << to_string(a.severity) << "\", \"ip\": \"" << json_escape(a.ip) << "\", \"detail\": \""
            << json_escape(a.detail) << "\", \"first_seen\": \"" << format_timestamp(a.first_seen)
            << "\", \"last_seen\": \"" << format_timestamp(a.last_seen) << "\", \"count\": " << a.event_count
            << "}";
    }
    out << (alerts.empty() ? "]\n}\n" : "\n  ]\n}\n");
}

}  // namespace logsentry
