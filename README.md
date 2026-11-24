# LogSentry: SSH Brute-Force Detector in C++

![CI](https://github.com/ahmad-evans/logsentry/actions/workflows/ci.yml/badge.svg)

A fast command-line tool that scans Linux SSH authentication logs (`/var/log/auth.log`) and flags:

| Alert | Severity | What it means |
|---|---|---|
| `SUCCESS_AFTER_FAILURES` | CRITICAL | A login **succeeded** right after a burst of failures from the same IP: possible compromise |
| `BRUTE_FORCE` | HIGH | Many failed logins from one IP inside a short sliding window |
| `PASSWORD_SPRAY` | MEDIUM | One IP trying many different usernames |

```
$ ./logsentry samples/auth.log
==================== LogSentry Report ====================
Lines read:        571
SSH auth events:   388  (183 other lines skipped)
Failed logins:     267
Successful logins: 121
Unique source IPs: 8

ALERTS (4)
  [CRITICAL] SUCCESS_AFTER_FAILURES 192.0.2.77      Login succeeded as 'deploy' after 25 failed attempts
  [HIGH    ] BRUTE_FORCE            203.0.113.45    36 failed logins within 60s
  [HIGH    ] BRUTE_FORCE            192.0.2.77      25 failed logins within 60s
  [MEDIUM  ] PASSWORD_SPRAY         198.51.100.23   11 different usernames tried

TOP SOURCES OF FAILED LOGINS
  203.0.113.45       180
  203.0.113.200       30
  192.0.2.77          25
  ...
```

The sample log has 4 attacks planted in it plus normal employee traffic. LogSentry finds all 4 with **zero false positives**, and correctly ignores a "slow" attacker who stays under the rate limit (`203.0.113.200`).

## Highlights

- **Modern C++17:** `std::string_view` parsing with no copies, `std::optional`, `std::from_chars`, RAII, no raw `new`/`delete`
- **Fast and memory-flat:** streams the log line by line. **~4 million lines/sec, 13 MB peak memory** on a 1M-line (94 MB) log
- **Robust parsing:** handles malformed lines, Windows line endings, IPv6, leap days and logs that cross New Year
- **28 unit tests + an end-to-end test**, using a small test framework I wrote (no dependencies)
- **Debugged with gdb, AddressSanitizer, UBSan, valgrind and clang-tidy.** See the **[Debugging Log](docs/DEBUGGING.md)** for 5 real bugs and how each was found and fixed
- **CI on every push:** g++ and clang++ builds with `-Werror`, sanitizer build, valgrind leak check, clang-tidy
- Exit code `3` when a critical alert is found, so it can drive a cron job or alerting script

## Build & Run

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/logsentry samples/auth.log

# Options
./build/logsentry --threshold 10 --window 120 --spray 5 --json alerts.json /var/log/auth.log
cat /var/log/auth.log | ./build/logsentry -       # read from stdin
```

| Option | Default | Meaning |
|---|---|---|
| `--threshold N` | 5 | Failed logins inside the window that count as brute force |
| `--window S` | 60 | Sliding window size in seconds |
| `--spray N` | 4 | Distinct usernames from one IP that count as spraying |
| `--json FILE` | | Also write alerts as JSON (for a SIEM or dashboard) |

Exit codes: `0` OK · `1` file error · `2` bad arguments · `3` critical alert found

## Tests & Debugging Tools

```bash
ctest --test-dir build --output-on-failure                       # unit + end-to-end tests

cmake -S . -B build-asan -DENABLE_SANITIZERS=ON                  # AddressSanitizer + UBSan
cmake --build build-asan && ctest --test-dir build-asan

valgrind --leak-check=full ./build/logsentry_tests               # memory leaks
clang-tidy -p build src/*.cpp                                    # static analysis
```

## How It Works

```
auth.log ──▶ parse_stream()  ──each event──▶  Detector::process()  ──▶  report (text / JSON)
              │ parse_line(): string_view,      │ per-IP sliding window (std::deque)
              │   no allocations for skipped    │ per-IP distinct usernames (std::set)
              │   lines                         │ failures-since-last-success (10 min window)
              │ New Year rollover handling      │ one alert per (IP, type), updated in place
```

- **Sliding window:** each IP has a `std::deque` of recent failure times. New failures push to the back, and anything older than the window pops off the front, so checking the window is O(1) amortized.
- **Library + app split:** all logic lives in `logsentry_core`, which both the CLI and the tests link against, so the tests exercise the exact code that ships.

## Project Structure

```
include/logsentry/   public headers (event, parser, detector, report)
src/                 implementation + main.cpp (CLI)
tests/               test framework + parser and detector tests
samples/             generate_sample_log.py + auth.log with planted attacks
docs/DEBUGGING.md    bugs found and how they were fixed
.github/workflows/   CI pipeline
```

## Limitations

- Supports the standard OpenSSH `auth.log` format (Debian/Ubuntu). `journalctl` JSON output isn't supported yet.
- Syslog timestamps have no year. Logs spanning more than a year, or a non-leap-year Feb 28 → Mar 1 boundary, can be off by a day.

---
Ahmad Evans · M.S. Information Systems & Business Analytics, Park University
