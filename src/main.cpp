// logsentry: scans SSH auth logs for brute-force attacks, password spraying,
// and successful logins from attacking IPs.
//
// Usage: logsentry [options] <logfile | ->
//   --threshold N   failed logins in the window that count as brute force (default 5)
//   --window S      sliding window in seconds (default 60)
//   --spray N       distinct usernames from one IP that count as spraying (default 4)
//   --json FILE     also write alerts as JSON
//   -h, --help

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include "logsentry/detector.hpp"
#include "logsentry/parser.hpp"
#include "logsentry/report.hpp"

namespace {

void usage(std::ostream& out) {
    out << "Usage: logsentry [--threshold N] [--window SECONDS] [--spray N] [--json FILE] <logfile | ->\n";
}

std::size_t to_positive(const std::string& flag, const std::string& value) {
    try {
        std::size_t pos = 0;
        long long n = std::stoll(value, &pos);
        if (pos != value.size() || n <= 0) throw std::invalid_argument("not positive");
        return static_cast<std::size_t>(n);
    } catch (const std::exception&) {
        throw std::runtime_error(flag + " needs a positive whole number, got '" + value + "'");
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    logsentry::DetectorConfig cfg;
    std::string input, json_path;

    try {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            auto need_value = [&]() -> std::string {
                if (i + 1 >= argc) throw std::runtime_error(arg + " needs a value");
                return argv[++i];
            };
            if (arg == "-h" || arg == "--help") {
                usage(std::cout);
                return 0;
            } else if (arg == "--threshold") {
                cfg.brute_force_threshold = to_positive(arg, need_value());
            } else if (arg == "--window") {
                cfg.brute_force_window = static_cast<std::int64_t>(to_positive(arg, need_value()));
            } else if (arg == "--spray") {
                cfg.spray_user_threshold = to_positive(arg, need_value());
            } else if (arg == "--json") {
                json_path = need_value();
            } else if (!arg.empty() && arg[0] == '-' && arg != "-") {
                throw std::runtime_error("unknown option " + arg);
            } else {
                input = arg;
            }
        }
        if (input.empty()) throw std::runtime_error("no log file given");
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        usage(std::cerr);
        return 2;
    }

    std::ifstream file;
    std::istream* in = &std::cin;
    if (input != "-") {
        file.open(input);
        if (!file) {
            std::cerr << "error: cannot open " << input << "\n";
            return 1;
        }
        in = &file;
    }

    // Stream: each event goes straight to the detector, so memory doesn't grow with file size
    logsentry::ParseStats stats;
    logsentry::Detector detector(cfg);
    logsentry::parse_stream(*in, stats, [&detector](logsentry::AuthEvent&& ev) { detector.process(ev); });
    logsentry::write_text_report(std::cout, stats, detector);

    if (!json_path.empty()) {
        std::ofstream json(json_path);
        if (!json) {
            std::cerr << "error: cannot write " << json_path << "\n";
            return 1;
        }
        logsentry::write_json_report(json, stats, detector);
    }

    // Exit code 3 when critical alerts exist, so scripts / cron jobs can react
    for (const auto& a : detector.alerts()) {
        if (a.severity == logsentry::Severity::Critical) return 3;
    }
    return 0;
}
