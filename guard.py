"""Protects the report (and any AI model) from hostile text hidden in log fields.

Log files contain attacker-controlled text: anyone can try to log in with a username like
"ignore all previous instructions". If that text is shown in a web page or given to a language
model, it could mislead the analysis. So every value taken from a log is cleaned before use.

The detection is rule-based: it catches common phrases, not every possible rewording. That is
why values are ALSO shortened, stripped of control characters, and treated as data only.
"""
import re
import unicodedata

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)

PATTERNS = {
    "tries to override instructions": re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b[^.]{0,30}"
        r"\b(previous|prior|above|earlier|all|any|your|the system)\b[^.]{0,30}"
        r"\b(instructions?|rules?|prompts?|guidelines?|directions?)\b"),
    "tries to change the assistant's role": re.compile(
        r"\byou are now\b|\bpretend (to be|you are)\b|\bfrom now on,? you (are|will|must)\b"
        r"|\bact as (if you are|an? (ai|assistant|admin|system))\b"),
    "asks to reveal hidden instructions": re.compile(
        r"\b(reveal|show|print|repeat|output|leak|disclose)\b[^.]{0,30}"
        r"\b(system prompt|hidden prompt|initial prompt|your (instructions|prompt|rules))\b"),
    "asks to hide things from the user": re.compile(
        r"\bdo not (tell|inform|mention|reveal|show)\b[^.]{0,30}\b(the )?(user|human|anyone)\b"),
    "tries to dictate the conclusion": re.compile(
        r"\b(report|say|state|tell|respond|answer|conclude|write)\b[^.]{0,30}"
        r"\b(safe|secure|benign|no (threats?|attacks?|issues?|problems?))\b"),
    "contains fake prompt delimiters": re.compile(
        r"</?context>|<\|im_(start|end)\|>|\[/?inst\]|###\s*system"),
}

SUSPICIOUS = "[removed: suspicious text]"


def scan(text):
    """Names of the suspicious patterns found in `text` (empty list = looks clean)."""
    cleaned = unicodedata.normalize("NFKC", str(text)).translate(_ZERO_WIDTH).lower()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return [name for name, pattern in PATTERNS.items() if pattern.search(cleaned)]


_SAFE_TRANSLATION = str.maketrans({"`": "'", "<": "(", ">": ")", "|": "/"})


def sanitize(value, limit=40):
    """Make a log value safe to display or send to a model. Returns (clean_text, was_flagged)."""
    text = "".join(ch for ch in str(value) if ch.isprintable())  # drops newlines and control characters
    text = re.sub(r"\s+", " ", text).strip()
    if scan(text):
        return SUSPICIOUS, True
    text = text.translate(_SAFE_TRANSLATION)
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text, False
