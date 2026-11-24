"""
Generates a realistic SSH auth.log with known attacks planted in it,
so the analyzer's output can be checked against the truth.

    python samples/generate_sample_log.py > samples/auth.log

Planted scenarios (attacker IPs use reserved documentation ranges):
  203.0.113.45   fast brute force on root (many tries per minute)       -> BRUTE_FORCE
  198.51.100.23  password spray: 1 try each on many usernames           -> PASSWORD_SPRAY
  192.0.2.77     brute force on 'deploy' that then SUCCEEDS              -> BRUTE_FORCE + SUCCESS_AFTER_FAILURES
  203.0.113.200  slow attacker: 1 try every 2 minutes                    -> should NOT trigger brute force
  10.0.0.x       normal employees, occasional typo                      -> nothing
"""
import random
from datetime import datetime, timedelta

random.seed(7)
HOST = "web01"
START = datetime(2026, 11, 23, 8, 0, 0)
lines = []
pid = 3000


def emit(t, msg, proc="sshd"):
    global pid
    pid += random.randint(1, 4)
    lines.append((t, f"{t:%b} {t.day:>2} {t:%H:%M:%S} {HOST} {proc}[{pid}]: {msg}"))


def port():
    return random.randint(30000, 65000)


# Normal day: employees logging in, a few typos, cron noise
employees = {"ahmad": "10.0.0.12", "maria": "10.0.0.15", "deploy": "10.0.0.4", "jlee": "10.0.0.21"}
for _ in range(120):
    t = START + timedelta(seconds=random.randint(0, 10 * 3600))
    user, ip = random.choice(list(employees.items()))
    if random.random() < 0.1:
        emit(t, f"Failed password for {user} from {ip} port {port()} ssh2")
        t += timedelta(seconds=random.randint(3, 15))
    method = "publickey" if random.random() < 0.6 else "password"
    emit(t, f"Accepted {method} for {user} from {ip} port {port()} ssh2")
    emit(t, f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)")
for i in range(60):
    emit(START + timedelta(minutes=10 * i), "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", "CRON")

# 1) Fast brute force on root
t = START + timedelta(hours=2, minutes=14)
for _ in range(180):
    t += timedelta(seconds=random.uniform(0.5, 3))
    emit(t, f"Failed password for root from 203.0.113.45 port {port()} ssh2")
emit(t, "Connection closed by authenticating user root 203.0.113.45 port 50122 [preauth]")

# 2) Password spray: many usernames, one attempt each, spread out
t = START + timedelta(hours=4)
for user in ["admin", "test", "oracle", "postgres", "ubuntu", "guest", "ftp", "pi", "user", "git", "jenkins"]:
    t += timedelta(seconds=random.randint(40, 90))
    emit(t, f"Invalid user {user} from 198.51.100.23 port {port()}")
    emit(t, f"Failed password for invalid user {user} from 198.51.100.23 port {port()} ssh2")

# 3) Brute force that succeeds: possible compromise
t = START + timedelta(hours=6, minutes=41)
for _ in range(25):
    t += timedelta(seconds=random.uniform(1, 4))
    emit(t, f"Failed password for deploy from 192.0.2.77 port {port()} ssh2")
t += timedelta(seconds=3)
emit(t, f"Accepted password for deploy from 192.0.2.77 port {port()} ssh2")

# 4) Slow attacker: stays under the brute-force rate on purpose
t = START + timedelta(hours=1)
for _ in range(30):
    t += timedelta(seconds=120)
    emit(t, f"Failed password for root from 203.0.113.200 port {port()} ssh2")

# A few malformed / truncated lines (real logs have these)
lines.append((START + timedelta(hours=9), "Nov 23 17:00:00 web01 sshd[9999]: Failed password for"))
lines.append((START + timedelta(hours=9), "#### log rotated ####"))

lines.sort(key=lambda x: x[0])
print("\n".join(line for _, line in lines))
