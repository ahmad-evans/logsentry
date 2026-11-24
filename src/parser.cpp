#include "logsentry/parser.hpp"

#include <array>
#include <charconv>
#include <string>

namespace logsentry {

namespace {

constexpr std::array<std::string_view, 12> kMonths = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
// Days before each month. Syslog lines have no year, so we always leave room for Feb 29
// (a 366-day layout). Otherwise "Feb 29" and "Mar 1" would map to the same second.
constexpr std::array<int, 12> kDaysBefore = {0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335};
constexpr std::array<int, 12> kDaysIn = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

bool parse_int(std::string_view s, int& out) {
    if (s.empty()) return false;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
    return ec == std::errc{} && ptr == s.data() + s.size();
}

std::string_view trim_left(std::string_view s) {
    while (!s.empty() && s.front() == ' ') s.remove_prefix(1);
    return s;
}

// Returns the next space-separated word and advances `s` past it.
std::string_view next_word(std::string_view& s) {
    s = trim_left(s);
    auto end = s.find(' ');
    auto word = s.substr(0, end);
    s.remove_prefix(end == std::string_view::npos ? s.size() : end);
    return word;
}

// After `marker`, read "<user> from <ip>". Returns false if the shape doesn't match.
bool read_user_from_ip(std::string_view rest, std::string& user, std::string& ip) {
    auto u = next_word(rest);
    if (next_word(rest) != "from") return false;
    auto addr = next_word(rest);
    if (u.empty() || addr.empty()) return false;
    user.assign(u);
    ip.assign(addr);
    return true;
}

}  // namespace

std::optional<std::int64_t> parse_timestamp(std::string_view text) {
    // Expected: "Mmm dd hh:mm:ss" (day may be space-padded: "Nov  3")
    if (text.size() < 15) return std::nullopt;
    auto mon = text.substr(0, 3);
    std::size_t month = kMonths.size();  // "not found"
    for (std::size_t i = 0; i < kMonths.size(); ++i) {
        if (kMonths[i] == mon) month = i;
    }
    if (month == kMonths.size() || text[3] != ' ') return std::nullopt;

    int day = 0, hh = 0, mm = 0, ss = 0;
    if (!parse_int(trim_left(text.substr(4, 2)), day)) return std::nullopt;
    if (text[6] != ' ' || text[9] != ':' || text[12] != ':') return std::nullopt;
    if (!parse_int(text.substr(7, 2), hh) || !parse_int(text.substr(10, 2), mm) ||
        !parse_int(text.substr(13, 2), ss)) {
        return std::nullopt;
    }
    if (day < 1 || day > kDaysIn[month] || hh > 23 || mm > 59 || ss > 59) return std::nullopt;

    std::int64_t days = kDaysBefore[month] + (day - 1);
    return ((days * 24 + hh) * 60 + mm) * 60 + ss;
}

std::optional<AuthEvent> parse_line(std::string_view line, std::size_t line_number) {
    // Only sshd lines matter: "Nov 23 14:02:11 host sshd[1234]: <message>"
    auto sshd = line.find(" sshd[");
    if (sshd == std::string_view::npos) return std::nullopt;
    auto colon = line.find("]: ", sshd);
    if (colon == std::string_view::npos) return std::nullopt;

    auto ts = parse_timestamp(line.substr(0, 15));
    if (!ts) return std::nullopt;

    AuthEvent ev;
    ev.timestamp = *ts;
    ev.line_number = line_number;
    std::string_view msg = line.substr(colon + 3);

    constexpr std::string_view kFailedInvalid = "Failed password for invalid user ";
    constexpr std::string_view kFailed = "Failed password for ";
    constexpr std::string_view kInvalid = "Invalid user ";
    constexpr std::string_view kAcceptedPw = "Accepted password for ";
    constexpr std::string_view kAcceptedKey = "Accepted publickey for ";

    auto starts = [&](std::string_view p) { return msg.substr(0, p.size()) == p; };

    // Order matters: the "invalid user" form must be checked before the plain one.
    if (starts(kFailedInvalid)) {
        ev.type = EventType::FailedPassword;
        if (!read_user_from_ip(msg.substr(kFailedInvalid.size()), ev.user, ev.ip)) return std::nullopt;
    } else if (starts(kFailed)) {
        ev.type = EventType::FailedPassword;
        if (!read_user_from_ip(msg.substr(kFailed.size()), ev.user, ev.ip)) return std::nullopt;
    } else if (starts(kInvalid)) {
        ev.type = EventType::InvalidUser;
        if (!read_user_from_ip(msg.substr(kInvalid.size()), ev.user, ev.ip)) return std::nullopt;
    } else if (starts(kAcceptedPw)) {
        ev.type = EventType::AcceptedLogin;
        if (!read_user_from_ip(msg.substr(kAcceptedPw.size()), ev.user, ev.ip)) return std::nullopt;
    } else if (starts(kAcceptedKey)) {
        ev.type = EventType::AcceptedLogin;
        if (!read_user_from_ip(msg.substr(kAcceptedKey.size()), ev.user, ev.ip)) return std::nullopt;
    } else {
        return std::nullopt;
    }
    return ev;
}

void parse_stream(std::istream& in, ParseStats& stats, const std::function<void(AuthEvent&&)>& on_event) {
    // Syslog timestamps have no year. If time suddenly jumps back by months (Dec 31 -> Jan 1),
    // the log crossed New Year, so add a year to keep timestamps increasing.
    constexpr std::int64_t kYear = 366LL * 86400;
    constexpr std::int64_t kRolloverGap = 180LL * 86400;
    std::int64_t year_offset = 0;
    std::int64_t last = 0;
    bool have_last = false;

    std::string line;
    while (std::getline(in, line)) {
        ++stats.total_lines;
        if (!line.empty() && line.back() == '\r') line.pop_back();  // tolerate Windows line endings
        if (auto ev = parse_line(line, stats.total_lines)) {
            if (have_last && ev->timestamp + year_offset < last - kRolloverGap) year_offset += kYear;
            ev->timestamp += year_offset;
            last = ev->timestamp;
            have_last = true;
            ++stats.events;
            on_event(std::move(*ev));
        } else {
            ++stats.skipped;
        }
    }
}

std::vector<AuthEvent> parse_stream(std::istream& in, ParseStats& stats) {
    std::vector<AuthEvent> events;
    parse_stream(in, stats, [&events](AuthEvent&& ev) { events.push_back(std::move(ev)); });
    return events;
}

}  // namespace logsentry
