#include "logsentry/detector.hpp"

#include <string>

namespace logsentry {

const char* to_string(EventType t) {
    switch (t) {
        case EventType::FailedPassword: return "FailedPassword";
        case EventType::InvalidUser: return "InvalidUser";
        case EventType::AcceptedLogin: return "AcceptedLogin";
    }
    return "Unknown";
}

const char* to_string(AlertType t) {
    switch (t) {
        case AlertType::BruteForce: return "BRUTE_FORCE";
        case AlertType::PasswordSpray: return "PASSWORD_SPRAY";
        case AlertType::SuccessAfterFails: return "SUCCESS_AFTER_FAILURES";
    }
    return "UNKNOWN";
}

const char* to_string(Severity s) {
    switch (s) {
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

Detector::Detector(DetectorConfig config) : config_(config) {}

void Detector::process_all(const std::vector<AuthEvent>& events) {
    for (const auto& e : events) process(e);
}

void Detector::raise_or_update(AlertType type, Severity sev, const std::string& ip,
                               const std::string& detail, std::int64_t ts, std::size_t count) {
    auto key = std::make_pair(ip, type);
    auto it = alert_index_.find(key);
    if (it == alert_index_.end()) {
        alert_index_[key] = alerts_.size();
        alerts_.push_back(Alert{type, sev, ip, detail, ts, ts, count});
        return;
    }
    Alert& a = alerts_[it->second];
    a.last_seen = ts;
    a.event_count = count;
    a.detail = detail;
}

void Detector::process(const AuthEvent& e) {
    IpStats& s = stats_[e.ip];
    if (s.failures + s.successes == 0) s.first_seen = e.timestamp;
    s.last_seen = e.timestamp;

    if (e.type == EventType::AcceptedLogin) {
        ++s.successes;
        // A success right after a burst of failures from the same IP is the most important thing
        // to catch. Only failures from the last `compromise_window` seconds count, and a successful
        // login resets the count, so an employee's occasional typos never add up to an alert.
        auto& fails = fails_since_success_[e.ip];
        while (!fails.empty() && e.timestamp - fails.front() > config_.compromise_window) {
            fails.pop_front();
        }
        if (fails.size() >= config_.compromise_min_failures) {
            raise_or_update(AlertType::SuccessAfterFails, Severity::Critical, e.ip,
                            "Login succeeded as '" + e.user + "' after " + std::to_string(fails.size()) +
                                " failed attempts",
                            e.timestamp, fails.size());
        }
        fails.clear();
        return;
    }

    // FailedPassword or InvalidUser
    ++s.failures;
    s.users_tried.insert(e.user);
    // Trim as we go so an attacker who never succeeds can't grow this list forever
    auto& since_success = fails_since_success_[e.ip];
    since_success.push_back(e.timestamp);
    while (e.timestamp - since_success.front() > config_.compromise_window) since_success.pop_front();

    // Sliding window: keep only failures from the last `brute_force_window` seconds
    auto& window = recent_failures_[e.ip];
    window.push_back(e.timestamp);
    while (!window.empty() && e.timestamp - window.front() > config_.brute_force_window) {
        window.pop_front();
    }
    if (window.size() >= config_.brute_force_threshold) {
        raise_or_update(AlertType::BruteForce, Severity::High, e.ip,
                        std::to_string(window.size()) + " failed logins within " +
                            std::to_string(config_.brute_force_window) + "s",
                        e.timestamp, s.failures);
    }

    if (s.users_tried.size() >= config_.spray_user_threshold) {
        raise_or_update(AlertType::PasswordSpray, Severity::Medium, e.ip,
                        std::to_string(s.users_tried.size()) + " different usernames tried", e.timestamp,
                        s.users_tried.size());
    }
}

}  // namespace logsentry
