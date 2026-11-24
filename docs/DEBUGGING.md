# Debugging Log

Real bugs found while building LogSentry: how each one showed up, how it was tracked down, and how it was fixed. Every fix has a test so the bug can't come back.

**Tools used:** unit tests, gdb, AddressSanitizer + UndefinedBehaviorSanitizer, valgrind, clang-tidy, and strict compiler warnings (`-Wall -Wextra -Wconversion -Wsign-conversion -Werror`).

---

## Bug 1: Signed integers used as array indexes

**Found by:** the compiler, on the very first build. `-Wsign-conversion -Werror` stopped the build.

```
parser.cpp:56: error: conversion to 'size_type' from 'int' may change the sign of the result
report.cpp:24: error: conversion to 'size_type' from 'int' may change the sign of the result
```

**Cause:** the month lookup used `int month = -1` as a "not found" marker, then used it to index `std::array`. If the "not found" check were ever skipped, `-1` would turn into a huge unsigned index and read out of bounds.

**Fix:** switched to `std::size_t` and used `kMonths.size()` as the "not found" value, so the index type can never be negative.

---

## Bug 2: February 29 and March 1 were the same timestamp

**Found by:** a unit test I wrote specifically to probe calendar edge cases (`leap_day_is_distinct_from_march_1`).

```
FAIL  leap_day_is_distinct_from_march_1
      test_parser.cpp:115: CHECK(*feb29 < *mar1) failed
```

**Cause:** syslog lines have no year, so the parser has to accept `Feb 29`, but the days-before-each-month table used a 365-day year. `Feb 29` (31 + 28 = day 59) landed on the same day as `Mar 1`, so events on those two days got mixed together.

**Fix:** use a 366-day layout in both the parser and the formatter, so every calendar date gets its own slot.

**Trade-off:** in non-leap years, Feb 28 → Mar 1 shows as a 2-day gap instead of 1. That only matters for a brute-force window that straddles that exact midnight, which is acceptable and noted in the README.

---

## Bug 3: Time went backwards at New Year → false brute-force alerts

**Found by:** two unit tests (`new_year_rollover_keeps_time_moving_forward` and `slow_attacker_across_new_year_is_not_brute_force`).

```
FAIL  new_year_rollover_keeps_time_moving_forward
      CHECK_EQ(events[1].timestamp - events[0].timestamp, 20) failed: -31535980 != 20
FAIL  slow_attacker_across_new_year_is_not_brute_force
      CHECK(d.alerts().empty()) failed
```

The first failure made sense (no year in the timestamp). The second needed more digging: why would a *slow* attacker set off a brute-force alert just because the log crossed midnight?

**Investigation with gdb:** I set a conditional breakpoint on the alert check, filtered to the attacker's IP, and printed the sliding window:

```
(gdb) break detector.cpp:82 if window.size() >= 5 && $_streq(e.ip._M_dataplus._M_p, "7.7.7.7")
(gdb) run
Breakpoint 1, logsentry::Detector::process (...) at detector.cpp:82
(gdb) print e.timestamp
$1 = 0
(gdb) print window.front()
$2 = 31535920
(gdb) print e.timestamp - window.front()
$3 = -31535920
(gdb) print window
$5 = std::deque with 5 elements = {31535920, 31535940, 31535960, 31535980, 0}
```

**Cause:** the window drops old entries with `while (now - front > 60) pop_front();`. After midnight, `now` is `0` and `front` is about 31.5 million, so the difference is **negative** and nothing is ever dropped. Old Dec 31 attempts piled up until there were 5 "within 60 seconds."

**Fix:** fixed at the source in `parse_stream`. If the time jumps *backwards* by more than 180 days, the log crossed New Year, so a year is added to every timestamp after that point. Time now always moves forward.

---

## Bug 4: Normal employees flagged as CRITICAL "possible compromise"

**Found by:** running the tool on the generated sample log, where I knew exactly which attacks were planted. It reported 7 alerts when there should have been 4:

```
[CRITICAL] SUCCESS_AFTER_FAILURES 10.0.0.21  Login succeeded as 'jlee' after 4 failed attempts
[CRITICAL] SUCCESS_AFTER_FAILURES 10.0.0.4   Login succeeded as 'deploy' after 3 failed attempts
[CRITICAL] SUCCESS_AFTER_FAILURES 10.0.0.15  Login succeeded as 'maria' after 3 failed attempts
```

Those are internal employee IPs with a normal typo here and there.

**Cause:** a logic bug. The rule checked the IP's **lifetime** failure count. An employee who mistyped their password once in the morning, once at lunch and once in the afternoon looked exactly like an attacker who failed 3 times and then broke in.

**Fix:**
1. Wrote regression tests that reproduce it (`occasional_typos_over_a_day_are_not_a_compromise`, `old_failures_outside_compromise_window_do_not_count`) and confirmed they failed.
2. Changed the rule: only failures in the **10 minutes before** a successful login count, and a successful login resets the count.
3. Result: exactly the 4 planted alerts, 0 false positives.

**Lesson:** unit tests check what you thought of. Running on realistic data with a known answer catches what you didn't.

---

## Bug 5: Unbounded memory growth for persistent attackers

**Found by:** code review while fixing Bug 4.

**Cause:** the new list of "failures since last success" was only cleared on a successful login. An attacker who never gets in would grow that list forever, one entry per attempt.

**Fix:** trim entries older than the 10-minute window on every failure, so each IP's list stays small.

---

## Improvement: memory use cut from 149 MB to 13 MB

**Found by:** benchmarking a 1-million-line (94 MB) log.

| Version | Time | Peak memory |
|---|---|---|
| Parse whole file into a vector, then analyze | 0.35 s | 149 MB |
| Stream each event straight to the detector | 0.24 s | 13 MB |

**Change:** added a streaming `parse_stream()` that hands each event to a callback as soon as it's parsed. Memory now stays flat no matter how big the log is, and it got faster too (no big vector to grow and copy).

---

## Static analysis findings (clang-tidy)

`performance-enum-size` flagged three enums using a 4-byte `int` when 1 byte is enough. Changed them to `enum class ... : std::uint8_t`. Not a bug, but it reduces the size of every event and alert.

## Final checks (all clean)

| Check | Result |
|---|---|
| Unit tests | 28/28 pass |
| End-to-end test on sample log | Pass |
| AddressSanitizer + UBSan (tests, sample log, garbage input) | No errors |
| valgrind `--leak-check=full` | No leaks, no invalid reads/writes |
| clang-tidy (bugprone, performance, clang-analyzer) | No warnings |
| g++ and clang++ with `-Werror` | Clean |
