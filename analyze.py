"""Analyze an SSH authentication log.

    python analyze.py sample_logs/ssh_bruteforce.log
    python analyze.py /var/log/auth.log --year 2026
    python analyze.py sample_logs/ssh_bruteforce.log --llm      (optional local LLM via Ollama)
"""
import argparse
import sys
from collections import Counter
from pathlib import Path

from detectors import detect
from log_parser import parse_log
from rag import KnowledgeBase, LLMUnavailable, attack_id, build_prompt, call_ollama, explain, load_knowledge

DEFAULT_KB = Path(__file__).parent / "knowledge_base" / "security_patterns.md"


def analyze_log(lines, kb, year=None, use_llm=False, model="llama3.2:1b"):
    """Full pipeline: parse -> detect -> retrieve knowledge -> explain. Returns a plain dict."""
    events, parse_stats = parse_log(lines, year)
    failed = Counter(e.ip for e in events if e.kind == "failed")
    stats = {
        "lines": parse_stats["lines"], "ignored": parse_stats["ignored"], "events": len(events),
        "failed": sum(failed.values()), "accepted": sum(1 for e in events if e.kind == "accepted"),
        "unique_ips": len({e.ip for e in events}), "failed_by_ip": failed.most_common(10),
    }
    items = []
    for finding in detect(events):
        hits = kb.search(finding.description, k=2)
        meaning, response = explain(finding, hits)
        items.append({"finding": finding, "hits": hits, "meaning": meaning, "response": response})

    counts = Counter(i["finding"].severity for i in items)
    summary = (f"{len(items)} finding(s): {counts.get('high', 0)} high, {counts.get('medium', 0)} medium."
               if items else "No suspicious authentication activity was found.")
    mode = "template"
    if use_llm and items:
        try:
            summary = call_ollama(build_prompt(items), model)
            mode = f"LLM ({model})"
        except LLMUnavailable:
            mode = "template (the local LLM was not reachable)"
    return {"stats": stats, "items": items, "summary": summary, "mode": mode}


def render_text(report, name="log"):
    s = report["stats"]
    out = [f"RAG Log Analyzer: {name}",
           f"Lines: {s['lines']}  |  SSH events parsed: {s['events']} (failed {s['failed']}, accepted {s['accepted']})"
           f"  |  unique IPs: {s['unique_ips']}  |  other lines ignored: {s['ignored']}",
           "", f"Summary ({report['mode']}): {report['summary']}", ""]
    for item in report["items"]:
        f = item["finding"]
        out.append(f"[{f.severity.upper()}] {f.title}")
        out.extend(f"    - {line}" for line in f.evidence)
        out.append(f"    What it means: {item['meaning']}")
        if item["response"]:
            out.append(f"    Recommended response: {item['response']}")
        if item["hits"]:
            refs = "; ".join(f"{e.title} ({attack_id(e)}, match {score:.2f})" for e, score in item["hits"])
            out.append(f"    Retrieved knowledge: {refs}")
        out.append("")
    return "\n".join(out)


def main():
    p = argparse.ArgumentParser(description="Analyze an SSH authentication log.")
    p.add_argument("logfile")
    p.add_argument("--kb", default=str(DEFAULT_KB), help="knowledge base file")
    p.add_argument("--year", type=int, help="year of the log (syslog lines do not include one)")
    p.add_argument("--llm", action="store_true", help="write the summary with a local Ollama model")
    p.add_argument("--model", default="llama3.2:1b")
    args = p.parse_args()
    try:
        lines = Path(args.logfile).read_text(encoding="utf-8", errors="replace").splitlines()
        kb = KnowledgeBase(load_knowledge(args.kb))
    except OSError as exc:
        print(f"Error: {exc}")
        return 1
    print(render_text(analyze_log(lines, kb, args.year, args.llm, args.model), Path(args.logfile).name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
