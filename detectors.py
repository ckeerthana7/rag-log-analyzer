"""Rule-based detection. This is ordinary Python, not AI: every finding is backed by counted evidence.

(The retrieval step in rag.py then explains what each finding means and what to do about it.)
"""
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from guard import sanitize, scan

BRUTE_FORCE_MIN = 5          # failed attempts from one IP
BRUTE_FORCE_HIGH = 20
SPRAY_MIN_USERS = 5          # distinct usernames from one IP ...
SPRAY_MAX_PER_USER = 3       # ... with at most this many attempts each (on average)
SUCCESS_AFTER_FAILS = 5      # failures from an IP before a successful login from it
ROOT_FAILS_MIN = 3
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    description: str            # plain-English summary used as the retrieval query
    evidence: list = field(default_factory=list)
    ips: list = field(default_factory=list)
    count: int = 0


def _minutes(first, last):
    return max(1, round((last - first).total_seconds() / 60))


def _names(counter, n=5):
    return ", ".join(sanitize(name)[0] for name, _ in counter.most_common(n))


def detect(events):
    findings = []
    failed = [e for e in events if e.kind == "failed"]
    by_ip = defaultdict(list)
    for e in failed:
        by_ip[e.ip].append(e)

    for ip, items in sorted(by_ip.items(), key=lambda kv: -len(kv[1])):
        users = Counter(e.user for e in items)
        first, last = min(e.ts for e in items), max(e.ts for e in items)
        minutes = _minutes(first, last)
        spray = len(users) >= SPRAY_MIN_USERS and len(items) / len(users) <= SPRAY_MAX_PER_USER
        if len(items) >= BRUTE_FORCE_MIN and not spray:
            findings.append(Finding(
                "brute_force", "Possible SSH brute-force attack",
                "high" if len(items) >= BRUTE_FORCE_HIGH else "medium",
                "repeated failed password login attempts from one source IP address against the same few "
                "accounts at an automated rate of several attempts per minute, "
                "within a few minutes, password guessing",
                [f"{len(items)} failed login attempts from {ip}",
                 f"{len(users)} account(s) targeted: {_names(users)}",
                 f"Between {first:%H:%M:%S} and {last:%H:%M:%S} (about {minutes} min, "
                 f"{len(items) / minutes:.1f} attempts/min)"],
                [ip], len(items)))
        if spray:
            findings.append(Finding(
                "password_spraying", "Possible password spraying / username probing", "medium",
                "one source IP address tried many different usernames with only one or two password "
                "attempts each, spraying",
                [f"{len(items)} failed attempts from {ip} across {len(users)} different usernames",
                 f"Usernames tried include: {_names(users)}",
                 f"About {len(items) / len(users):.1f} attempts per username, between "
                 f"{first:%H:%M:%S} and {last:%H:%M:%S}"],
                [ip], len(items)))

    reported = set()
    for e in sorted((x for x in events if x.kind == "accepted"), key=lambda x: x.ts):
        before = [f for f in by_ip.get(e.ip, []) if f.ts <= e.ts]
        if len(before) >= SUCCESS_AFTER_FAILS and e.ip not in reported:
            reported.add(e.ip)
            findings.append(Finding(
                "success_after_failures", "Successful login after repeated failures (possible compromise)", "high",
                "a successful login from an IP address that previously had many failed login attempts, "
                "possible account compromise",
                [f"{len(before)} failed attempts from {e.ip} before a successful login",
                 f"Successful login as '{sanitize(e.user)[0]}' at {e.ts:%H:%M:%S} using {sanitize(e.method)[0]}"],
                [e.ip], len(before)))

    root = [e for e in failed if e.user == "root"]
    if len(root) >= ROOT_FAILS_MIN:
        ips = Counter(e.ip for e in root)
        findings.append(Finding(
            "root_targeting", "Repeated attempts to log in as root", "medium",
            "failed login attempts directly against the root account over SSH",
            [f"{len(root)} failed login attempts for root", f"From {len(ips)} IP address(es): {_names(ips)}"],
            list(ips), len(root)))

    hostile = Counter(e.user for e in events if scan(e.user))
    if hostile:
        findings.append(Finding(
            "log_injection", "Suspicious instruction-like text inside log fields", "medium",
            "log field contains instruction-like text intended to manipulate an AI log analysis tool, "
            "log injection, prompt injection",
            [f"{sum(hostile.values())} log line(s) have a username that looks like instructions to an AI",
             "The text was removed from this report and never sent to a language model"],
            sorted({e.ip for e in events if e.user in hostile}), sum(hostile.values())))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.count))
    return findings
