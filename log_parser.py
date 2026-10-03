"""Turns SSH authentication log lines (OpenSSH, as written to /var/log/auth.log) into events.

Supported timestamp styles:
    Oct  3 03:12:01 web01 sshd[2301]: Failed password for root from 203.0.113.45 port 40122 ssh2
    2026-10-03T03:12:01+00:00 web01 sshd[2301]: Failed password for root from ...
Lines that are not about sshd logins are counted and ignored.
"""
import re
from dataclasses import dataclass
from datetime import datetime

SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
                    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+"
                 r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
FAILED = re.compile(r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.+?) from (?P<ip>\S+) port (?P<port>\d+)")
ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>.+?) from (?P<ip>\S+) port (?P<port>\d+)")
INVALID = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?")


@dataclass(frozen=True)
class Event:
    ts: datetime
    host: str
    kind: str      # "failed", "accepted" or "invalid_user"
    user: str
    ip: str
    method: str
    line_no: int


def _timestamp(match, year):
    if "ts" in match.groupdict():
        return datetime.strptime(match.group("ts"), "%Y-%m-%dT%H:%M:%S")
    return datetime.strptime(f"{year} {match.group('mon')} {match.group('day')} {match.group('time')}",
                             "%Y %b %d %H:%M:%S")


def parse_log(lines, year=None):
    """Returns (events, stats). `year` is needed because syslog timestamps do not contain one."""
    year = year or datetime.now().year
    events, total, ignored = [], 0, 0
    for number, line in enumerate(lines, 1):
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        total += 1
        match = SYSLOG.match(line) or ISO.match(line)
        if not match or not match.group("proc").startswith("sshd"):
            ignored += 1
            continue
        message = match.group("msg")
        for kind, pattern in (("failed", FAILED), ("accepted", ACCEPTED), ("invalid_user", INVALID)):
            found = pattern.match(message)
            if found:
                try:
                    ts = _timestamp(match, year)
                except ValueError:
                    ignored += 1
                    break
                events.append(Event(ts, match.group("host"), kind, found.group("user"), found.group("ip"),
                                    found.groupdict().get("method") or "", number))
                break
        else:
            ignored += 1
    return events, {"lines": total, "ignored": ignored}
