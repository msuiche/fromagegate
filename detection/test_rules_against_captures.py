#!/usr/bin/env python3
"""
Functional check: replay captures/http-requests.jsonl against the Suricata
ruleset and report which SIDs fire on which captured requests.

This is NOT a Suricata engine test (no suricata binary on this host); it is
a minimal matcher for the rule constructs used in danfoss-aksm-cves.rules
(http.method, http.uri, http.request_body, content, pcre). Response-side
rules (http.stat_code) are structure-checked only. Run `suricata -T` and a
pcap replay in your lab for engine-level validation.

Usage: python3 detection/test_rules_against_captures.py
Exit 0 if every request-side rule fires on at least one expected capture.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "detection" / "suricata" / "danfoss-aksm-cves.rules"
CAPTURES = ROOT / "captures" / "http-requests.jsonl"


def parse_rules(path):
    rules = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"alert http .*?\((.*)\)\s*$", line)
        if not m:
            print(f"[struct] FAIL unparsable rule: {line[:80]}")
            sys.exit(1)
        body = m.group(1)
        # balanced-paren check already implied by regex; extract fields
        rule = {"raw": line, "contents": [], "buffers": []}
        rule["sid"] = int(re.search(r"sid:(\d+)", body).group(1))
        rule["msg"] = re.search(r'msg:"([^"]+)"', body).group(1)
        rule["contents"] = re.findall(r'content:"([^"]+)"', body)
        rule["buffers"] = re.findall(r"(http\.method|http\.uri|http\.request_body|http\.stat_code|http\.response_body);", body)
        pcre_m = re.search(r'pcre:"(/.*?/[a-z]*)";', body)
        if pcre_m:
            pat = pcre_m.group(1)
            # suricata escapes backslash as \\ in rule strings
            pat = pat.replace("\\\\", "\\")
            pm = re.match(r"/(.*)/([a-z]*)$", pat)
            flags = re.I if "i" in pm.group(2) else 0
            rule["pcre"] = re.compile(pm.group(1), flags)  # raises on bad pcre
        rules.append(rule)
    return rules


def field_text(rec, buffer):
    if buffer == "http.uri":
        return rec["path"]
    if buffer == "http.request_body":
        return rec["body"]
    if buffer == "http.method":
        return rec["method"]
    return ""  # response-side buffers not present in captures


def rule_fires(rule, rec):
    """Approximate Suricata matching for request-side rules."""
    buffers = rule["buffers"]
    if any(b in ("http.stat_code", "http.response_body") for b in buffers):
        return None  # response-side: not exercised here
    # associate contents with the preceding buffer in rule order
    tokens = re.findall(r'(http\.method|http\.uri|http\.request_body|content:"[^"]+"|pcre:"/.*?/[a-z]*");', rule["raw"])
    current = None
    for tok in tokens:
        if tok.startswith("http."):
            current = tok
        elif tok.startswith("content:"):
            needle = tok[len('content:"'):-1]
            hay = field_text(rec, current)
            if needle.lower() not in hay.lower():
                return False
        elif tok.startswith("pcre:"):
            hay = field_text(rec, current)
            if not rule["pcre"].search(hay):
                return False
    return True


def main():
    rules = parse_rules(RULES)
    print(f"[struct] parsed {len(rules)} rules, all PCREs compile")

    recs = [json.loads(line) for line in CAPTURES.read_text().splitlines()]
    print(f"[replay] {len(recs)} captured requests")

    fired = {}
    for rec in recs:
        for rule in rules:
            if rule_fires(rule, rec):
                fired.setdefault(rule["sid"], []).append(rec["path"])

    ok = True
    for rule in rules:
        sid, msg = rule["sid"], rule["msg"]
        if sid in fired:
            print(f"[FIRE]  sid {sid}: {len(fired[sid])} hit(s)  {msg}")
        elif any(b in ("http.stat_code", "http.response_body") for b in rule["buffers"]):
            print(f"[skip]  sid {sid}: response-side rule, not exercised by captures  {msg}")
        elif sid == 4414500 or sid == 4414530:
            # 4414500 should fire on any getauth; 4414530 is response-side handled above
            print(f"[MISS]  sid {sid}: expected hits  {msg}")
            ok = False
        else:
            print(f"[MISS]  sid {sid}: no hits in captures  {msg}")
            ok = False

    # false-positive spot check: the injection rules must NOT fire on the
    # plain wrong-password auth request
    for rec in recs:
        if "wrong-password" in rec["body"]:
            bad = [r["sid"] for r in rules if rule_fires(r, rec) and r["sid"] != 4414500]
            if bad:
                print(f"[FP]    baseline auth fired injection/bypass sids: {bad}")
                ok = False

    print("RESULT:", "OK" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
