#include <cstdio>
#include <sstream>
#include <string>

#include "logsentry/detector.hpp"
#include "logsentry/parser.hpp"
#include "test_framework.hpp"

using namespace logsentry;

namespace {

AuthEvent fail(const std::string& ip, std::int64_t t, const std::string& user = "root") {
    return AuthEvent{t, EventType::FailedPassword, user, ip, 0};
}
AuthEvent ok(const std::string& ip, std::int64_t t, const std::string& user = "root") {
    return AuthEvent{t, EventType::AcceptedLogin, user, ip, 0};
}

std::size_t count_type(const Detector& d, AlertType type) {
    std::size_t n = 0;
    for (const auto& a : d.alerts()) n += (a.type == type);
    return n;
}

}  // namespace

// ---------------------------------------------------------------- brute force

TEST(brute_force_fires_at_threshold) {
    Detector d(DetectorConfig{5, 60, 100, 3});
    for (int i = 0; i < 4; ++i) d.process(fail("1.1.1.1", i * 10));
    CHECK_EQ(count_type(d, AlertType::BruteForce), std::size_t{0});  // 4 is not enough
    d.process(fail("1.1.1.1", 40));
    CHECK_EQ(count_type(d, AlertType::BruteForce), std::size_t{1});
}

TEST(brute_force_window_edge_is_inclusive) {
    // 5 failures spanning exactly 60 seconds should count as "within 60s"
    Detector d(DetectorConfig{5, 60, 100, 3});
    for (int t : {0, 15, 30, 45, 60}) d.process(fail("1.1.1.1", t));
    CHECK_EQ(count_type(d, AlertType::BruteForce), std::size_t{1});
}

TEST(slow_attacker_outside_window_is_not_brute_force) {
    // One attempt every 20s: never 5 inside any 60s window
    Detector d(DetectorConfig{5, 60, 100, 3});
    for (int i = 0; i < 20; ++i) d.process(fail("1.1.1.1", i * 20));
    CHECK_EQ(count_type(d, AlertType::BruteForce), std::size_t{0});
}

TEST(failures_from_different_ips_are_tracked_separately) {
    Detector d(DetectorConfig{5, 60, 100, 3});
    for (int i = 0; i < 4; ++i) {
        d.process(fail("1.1.1.1", i));
        d.process(fail("2.2.2.2", i));
    }
    CHECK(d.alerts().empty());
}

TEST(one_alert_per_ip_updated_not_duplicated) {
    Detector d(DetectorConfig{5, 60, 100, 3});
    for (int i = 0; i < 50; ++i) d.process(fail("1.1.1.1", i));
    CHECK_EQ(count_type(d, AlertType::BruteForce), std::size_t{1});
    const Alert& a = d.alerts()[0];
    CHECK_EQ(a.first_seen, std::int64_t{4});
    CHECK_EQ(a.last_seen, std::int64_t{49});
    CHECK_EQ(a.event_count, std::size_t{50});
}

// ---------------------------------------------------------------- password spraying

TEST(password_spray_counts_distinct_users) {
    Detector d(DetectorConfig{100, 60, 4, 3});
    d.process(fail("9.9.9.9", 0, "root"));
    d.process(fail("9.9.9.9", 100, "root"));  // repeat user: doesn't count twice
    d.process(fail("9.9.9.9", 200, "admin"));
    d.process(fail("9.9.9.9", 300, "test"));
    CHECK_EQ(count_type(d, AlertType::PasswordSpray), std::size_t{0});
    d.process(fail("9.9.9.9", 400, "oracle"));
    CHECK_EQ(count_type(d, AlertType::PasswordSpray), std::size_t{1});
}

// ---------------------------------------------------------------- possible compromise

TEST(success_after_failures_is_critical) {
    Detector d(DetectorConfig{100, 60, 100, 3});
    for (int i = 0; i < 3; ++i) d.process(fail("6.6.6.6", i));
    d.process(ok("6.6.6.6", 10, "root"));
    CHECK_EQ(count_type(d, AlertType::SuccessAfterFails), std::size_t{1});
    CHECK(d.alerts().back().severity == Severity::Critical);
}

TEST(normal_login_with_one_typo_is_not_flagged) {
    Detector d(DetectorConfig{});
    d.process(fail("10.0.0.4", 0, "ahmad"));
    d.process(ok("10.0.0.4", 5, "ahmad"));
    CHECK(d.alerts().empty());
}

TEST(stats_track_first_and_last_seen) {
    Detector d;
    d.process(fail("1.1.1.1", 100));
    d.process(ok("1.1.1.1", 250));
    const auto& s = d.ip_stats().at("1.1.1.1");
    CHECK_EQ(s.first_seen, std::int64_t{100});
    CHECK_EQ(s.last_seen, std::int64_t{250});
    CHECK_EQ(s.failures, std::size_t{1});
    CHECK_EQ(s.successes, std::size_t{1});
}

TEST(success_first_then_failures_keeps_first_seen) {
    Detector d;
    d.process(ok("1.1.1.1", 100));
    d.process(fail("1.1.1.1", 200));
    CHECK_EQ(d.ip_stats().at("1.1.1.1").first_seen, std::int64_t{100});
}

TEST(slow_attacker_across_new_year_is_not_brute_force) {
    // Same slow attacker as above (one try every 20s), but the log crosses midnight on Dec 31.
    std::string log;
    for (int i = 0; i < 12; ++i) {
        int t = 23 * 3600 + 58 * 60 + i * 20;  // starts Dec 31 23:58:00
        int h = (t / 3600) % 24, m = (t / 60) % 60, s = t % 60;
        char line[160];
        std::snprintf(line, sizeof line, "%s %02d:%02d:%02d h sshd[1]: Failed password for root from 7.7.7.7 port 1 ssh2\n",
                      t < 24 * 3600 ? "Dec 31" : "Jan  1", h, m, s);
        log += line;
    }
    std::istringstream in(log);
    ParseStats stats;
    Detector d(DetectorConfig{5, 60, 100, 3});
    d.process_all(parse_stream(in, stats));
    CHECK_EQ(stats.events, std::size_t{12});
    CHECK(d.alerts().empty());
}

TEST(occasional_typos_over_a_day_are_not_a_compromise) {
    // Regression test: an employee mistypes once before each of 4 logins spread over the day.
    // Old behavior counted all failures since the start of the log and raised a CRITICAL alert.
    Detector d;
    for (int hour = 0; hour < 4; ++hour) {
        d.process(fail("10.0.0.21", hour * 3600, "jlee"));
        d.process(ok("10.0.0.21", hour * 3600 + 10, "jlee"));
    }
    CHECK(d.alerts().empty());
}

TEST(old_failures_outside_compromise_window_do_not_count) {
    Detector d(DetectorConfig{100, 60, 100, 3});
    for (int i = 0; i < 3; ++i) d.process(fail("5.5.5.5", i));
    d.process(ok("5.5.5.5", 2 * 3600));  // 2 hours later: unrelated
    CHECK(d.alerts().empty());
}
