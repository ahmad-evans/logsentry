#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "logsentry/event.hpp"

namespace logsentry {

struct DetectorConfig {
    std::size_t brute_force_threshold = 5;    // failures from one IP...
    std::int64_t brute_force_window = 60;     // ...within this many seconds
    std::size_t spray_user_threshold = 4;     // distinct usernames tried by one IP
    std::size_t compromise_min_failures = 3;  // failures right before a success to call it suspicious
    std::int64_t compromise_window = 600;     // "right before" = within this many seconds of the success
};

// Processes events in time order and raises alerts. Each IP gets at most one
// alert of each type; later activity updates that alert instead of duplicating it.
class Detector {
public:
    explicit Detector(DetectorConfig config = {});

    void process(const AuthEvent& event);
    void process_all(const std::vector<AuthEvent>& events);

    const std::vector<Alert>& alerts() const { return alerts_; }

    struct IpStats {
        std::size_t failures = 0;
        std::size_t successes = 0;
        std::set<std::string> users_tried;
        std::int64_t first_seen = 0;
        std::int64_t last_seen = 0;
    };
    const std::map<std::string, IpStats>& ip_stats() const { return stats_; }

private:
    void raise_or_update(AlertType type, Severity sev, const std::string& ip,
                         const std::string& detail, std::int64_t ts, std::size_t count);

    DetectorConfig config_;
    std::map<std::string, std::deque<std::int64_t>> recent_failures_;  // brute-force window per IP
    std::map<std::string, std::deque<std::int64_t>> fails_since_success_;  // reset on each successful login
    std::map<std::string, IpStats> stats_;
    std::map<std::pair<std::string, AlertType>, std::size_t> alert_index_;  // (ip, type) -> position in alerts_
    std::vector<Alert> alerts_;
};

}  // namespace logsentry
