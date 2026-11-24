#include <sstream>

#include "logsentry/parser.hpp"
#include "logsentry/report.hpp"
#include "test_framework.hpp"

using namespace logsentry;

// ---------------------------------------------------------------- timestamps

TEST(timestamp_start_of_year) { CHECK_EQ(*parse_timestamp("Jan  1 00:00:00"), 0); }

TEST(timestamp_known_value) {
    // Feb 2 = day 32 (0-based), 01:02:03
    CHECK_EQ(*parse_timestamp("Feb  2 01:02:03"), (32 * 24 + 1) * 3600 + 2 * 60 + 3);
}

TEST(timestamp_two_digit_day) { CHECK(parse_timestamp("Nov 23 14:02:11").has_value()); }

TEST(timestamp_rejects_bad_input) {
    CHECK(!parse_timestamp("").has_value());
    CHECK(!parse_timestamp("Foo 23 14:02:11").has_value());
    CHECK(!parse_timestamp("Nov 23 25:02:11").has_value());
    CHECK(!parse_timestamp("Nov 32 14:02:11").has_value());
    CHECK(!parse_timestamp("Feb 30 14:02:11").has_value());
    CHECK(!parse_timestamp("Nov 23 14-02-11").has_value());
    CHECK(!parse_timestamp("Nov xx 14:02:11").has_value());
}

TEST(timestamp_round_trip) {
    for (const char* t : {"Jan  1 00:00:00", "Feb 28 23:59:59", "Mar  1 00:00:00", "Nov 23 14:02:11",
                          "Dec 31 23:59:59"}) {
        CHECK_EQ(format_timestamp(*parse_timestamp(t)), std::string(t));
    }
}

// ---------------------------------------------------------------- log lines

TEST(parses_failed_password) {
    auto ev = parse_line("Nov 23 14:02:11 web01 sshd[2211]: Failed password for root from 203.0.113.5 port 51122 ssh2");
    CHECK(ev.has_value());
    CHECK(ev->type == EventType::FailedPassword);
    CHECK_EQ(ev->user, std::string("root"));
    CHECK_EQ(ev->ip, std::string("203.0.113.5"));
}

TEST(parses_failed_password_invalid_user) {
    auto ev = parse_line(
        "Nov 23 14:02:12 web01 sshd[2212]: Failed password for invalid user admin from 198.51.100.7 port 4022 ssh2");
    CHECK(ev.has_value());
    CHECK(ev->type == EventType::FailedPassword);
    CHECK_EQ(ev->user, std::string("admin"));  // not "invalid"
    CHECK_EQ(ev->ip, std::string("198.51.100.7"));
}

TEST(parses_invalid_user) {
    auto ev = parse_line("Nov 23 14:02:13 web01 sshd[2213]: Invalid user oracle from 198.51.100.7 port 4023");
    CHECK(ev.has_value());
    CHECK(ev->type == EventType::InvalidUser);
    CHECK_EQ(ev->user, std::string("oracle"));
}

TEST(parses_accepted_password_and_key) {
    auto a = parse_line("Nov 23 14:05:00 web01 sshd[2300]: Accepted password for deploy from 10.0.0.4 port 5000 ssh2");
    auto b = parse_line("Nov 23 14:05:01 web01 sshd[2301]: Accepted publickey for ahmad from 10.0.0.9 port 5001 ssh2: RSA SHA256:abc");
    CHECK(a && a->type == EventType::AcceptedLogin && a->user == "deploy" && a->ip == "10.0.0.4");
    CHECK(b && b->type == EventType::AcceptedLogin && b->user == "ahmad" && b->ip == "10.0.0.9");
}

TEST(parses_ipv6) {
    auto ev = parse_line("Nov 23 14:02:11 web01 sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2");
    CHECK(ev.has_value());
    CHECK_EQ(ev->ip, std::string("2001:db8::1"));
}

TEST(ignores_non_ssh_and_garbage) {
    CHECK(!parse_line("Nov 23 14:00:01 web01 CRON[999]: pam_unix(cron:session): session opened").has_value());
    CHECK(!parse_line("Nov 23 14:00:01 web01 sshd[1]: Connection closed by 203.0.113.5 port 1 [preauth]").has_value());
    CHECK(!parse_line("").has_value());
    CHECK(!parse_line("sshd[").has_value());
    CHECK(!parse_line("garbage sshd[1]: Failed password for root from 1.2.3.4").has_value());  // bad timestamp
    CHECK(!parse_line("Nov 23 14:00:01 web01 sshd[1]: Failed password for root").has_value());    // truncated
    CHECK(!parse_line("Nov 23 14:00:01 web01 sshd[1]: Failed password for ").has_value());
}

TEST(stream_counts_and_windows_line_endings) {
    std::istringstream in(
        "Nov 23 14:02:11 h sshd[1]: Failed password for root from 1.1.1.1 port 1 ssh2\r\n"
        "Nov 23 14:02:12 h CRON[2]: something else\n"
        "\n"
        "Nov 23 14:02:13 h sshd[3]: Accepted password for bob from 2.2.2.2 port 2 ssh2\n");
    ParseStats stats;
    auto events = parse_stream(in, stats);
    CHECK_EQ(stats.total_lines, std::size_t{4});
    CHECK_EQ(stats.events, std::size_t{2});
    CHECK_EQ(stats.skipped, std::size_t{2});
    CHECK_EQ(events[0].ip, std::string("1.1.1.1"));  // no trailing '\r'
    CHECK_EQ(events[1].line_number, std::size_t{4});
}

// ---------------------------------------------------------------- output helpers

TEST(json_escape_special_characters) {
    CHECK_EQ(json_escape("a\"b\\c\nd"), std::string("a\\\"b\\\\c\\nd"));
    CHECK_EQ(json_escape(std::string("x\x01y")), std::string("x\\u0001y"));
}

// ---------------------------------------------------------------- calendar edge cases

TEST(leap_day_is_distinct_from_march_1) {
    // Syslog lines have no year, so Feb 29 can appear. It must not collide with Mar 1.
    auto feb29 = parse_timestamp("Feb 29 12:00:00");
    auto mar1 = parse_timestamp("Mar  1 12:00:00");
    CHECK(feb29.has_value() && mar1.has_value());
    CHECK(*feb29 < *mar1);
    CHECK_EQ(format_timestamp(*feb29), std::string("Feb 29 12:00:00"));
}

TEST(new_year_rollover_keeps_time_moving_forward) {
    // A log that runs past midnight on Dec 31 must not jump back to "Jan 1 = time 0"
    std::istringstream in(
        "Dec 31 23:59:50 h sshd[1]: Failed password for root from 1.1.1.1 port 1 ssh2\n"
        "Jan  1 00:00:10 h sshd[2]: Failed password for root from 1.1.1.1 port 1 ssh2\n");
    ParseStats stats;
    auto events = parse_stream(in, stats);
    CHECK_EQ(events.size(), std::size_t{2});
    CHECK_EQ(events[1].timestamp - events[0].timestamp, std::int64_t{20});
}
