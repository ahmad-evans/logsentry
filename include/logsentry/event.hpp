#pragma once

#include <cstdint>
#include <string>

namespace logsentry {

enum class EventType : std::uint8_t { FailedPassword, InvalidUser, AcceptedLogin };

// One security-relevant line from an SSH auth log.
struct AuthEvent {
    std::int64_t timestamp = 0;  // seconds since the start of the year
    EventType type = EventType::FailedPassword;
    std::string user;
    std::string ip;
    std::size_t line_number = 0;
};

enum class Severity : std::uint8_t { Medium, High, Critical };

enum class AlertType : std::uint8_t {
    BruteForce,        // many failed logins from one IP in a short window
    PasswordSpray,     // one IP trying many different usernames
    SuccessAfterFails  // a login SUCCEEDED from an IP that was attacking: possible compromise
};

struct Alert {
    AlertType type;
    Severity severity;
    std::string ip;
    std::string detail;
    std::int64_t first_seen = 0;
    std::int64_t last_seen = 0;
    std::size_t event_count = 0;
};

const char* to_string(EventType t);
const char* to_string(AlertType t);
const char* to_string(Severity s);

}  // namespace logsentry
