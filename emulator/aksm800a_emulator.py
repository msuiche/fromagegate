#!/usr/bin/env python3
"""
Danfoss AK-SM 800A vulnerable-behavior emulator (pre-R4.2 / pre-R4.3.1).

Emulates, for detection-signature development, the three web-interface
weaknesses documented by Claroty Team82 and Danfoss advisories
DSA-2025-03-01 / DSA-2025-08-01:

  CVE-2025-41450  /xml.cgi?action=getauth accepts a "code of the day"
                  (datetime-derived password) instead of the configured
                  admin password when specific request attributes are set.
                  NOTE: Claroty redacted the real attribute names and the
                  real generation algorithm. This emulator implements the
                  documented *mechanism* with a stand-in algorithm
                  (cotd.generate_code) and stand-in attribute names
                  ("codeofday" / "support"). Swap in real values if you
                  recover them from firmware.

  CVE-2025-41451  alarm-to-mail / SMTP email configuration save handler
                  interpolates the email password field (config item
                  0x1be1) into an OS shell command without sanitization.

  CVE-2025-41452  action=load_nginx_headers accepts an authenticated
                  file upload replacing headers.conf, which is included by
                  the Internet-facing nginx instance. Injected location
                  blocks become live; requesting an injected route crashes
                  the web service task (sm_app) -> repeatable DoS.

Binds 127.0.0.1 only. Logs every request to captures/http-requests.jsonl
so you can diff PoC traffic against signatures.
"""

import json
import re
import shlex
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "captures"
STATE = ROOT / "emulator" / "state"
CAPTURES.mkdir(exist_ok=True)
STATE.mkdir(exist_ok=True)
LOG = CAPTURES / "http-requests.jsonl"

ADMIN_USER = "admin"
ADMIN_PASS = "Danfoss800A!"  # emulator-only configured password

BYPASS_ATTRIBUTES = ("codeofday", "support")  # stand-ins for redacted attrs
SESSIONS = {}

# set by CVE-2025-41452 handler
injected_locations = []          # list of location paths from uploaded headers.conf
injected_headers = []            # add_header directives from uploaded headers.conf
crashed_until = 0.0              # sm_app simulated crash window
CRASH_SECONDS = 8


def generate_code(day: datetime) -> str:
    """Stand-in code-of-the-day algorithm (real algorithm is not public).

    Documented property preserved from the research: the code depends ONLY
    on the device's current date, so anyone who can reproduce the algorithm
    can authenticate on any given day.
    """
    import hashlib

    seed = f"AKSM-COTD-{day.year:04d}-{day.month:02d}-{day.day:02d}"
    return f"{int(hashlib.md5(seed.encode()).hexdigest(), 16) % 900000 + 100000}"


def log_request(handler, body: bytes, tags):
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": handler.command,
        "path": handler.path,
        "client": handler.client_address[0],
        "headers": {k: v for k, v in handler.headers.items()},
        "body": body.decode("utf-8", "replace")[:4096],
        "tags": tags,
    }
    with LOG.open("a") as fh:
        fh.write(json.dumps(rec) + "\n")


def parse_body(handler, body: bytes) -> dict:
    ctype = handler.headers.get("Content-Type", "")
    if "application/x-www-form-urlencoded" in ctype:
        return {k: v[0] for k, v in urllib.parse.parse_qs(body.decode("utf-8", "replace")).items()}
    if "text/xml" in ctype or body.strip().startswith(b"<"):
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(body)
            return {child.tag: (child.text or "").strip() for child in root}
        except ET.ParseError:
            return {}
    return {}


def xml_response(result: str, extra: str = "") -> bytes:
    return f'<?xml version="1.0"?><response><result>{result}</result>{extra}</response>'.encode()


class AKSMHandler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""

    def version_string(self):
        return "nginx"  # AK-SM external interface fronts with nginx

    def log_message(self, *args):
        pass  # structured jsonl log instead

    # -- helpers ---------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype="text/xml", extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in injected_headers:  # live directives from uploaded headers.conf
            self.send_header(k, v)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _session(self) -> str:
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie(raw)
        morsel = jar.get("SMSession")
        if morsel and morsel.value in SESSIONS:
            return morsel.value
        return None

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    # -- request dispatch ------------------------------------------------
    def _dispatch(self):
        global crashed_until
        body = self._read_body()
        parsed = urllib.parse.urlsplit(self.path)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        tags = []

        # simulated post-crash window (CVE-2025-41452 DoS condition)
        if time.time() < crashed_until:
            tags.append("svc_unavailable_during_crash")
            log_request(self, body, tags)
            self._send(503, b"<h1>503 Service Unavailable</h1>", "text/html")
            return

        if parsed.path == "/" and self.command == "GET":
            log_request(self, body, tags)
            page = b"<html><head><title>StoreView - Login</title></head><body>AK-SM 800A</body></html>"
            self._send(200, page, "text/html")
            return

        if parsed.path == "/xml.cgi":
            action = params.get("action", "")
            if action == "getauth":
                return self._handle_getauth(body, params, tags)
            if action == "set_email_config":
                return self._handle_set_email_config(body, params, tags)
            if action == "load_nginx_headers":
                return self._handle_load_nginx_headers(body, tags)
            log_request(self, body, ["unknown_action"])
            self._send(400, xml_response("error", "<error>unknown action</error>"))
            return

        # injected nginx locations (CVE-2025-41452): hitting one crashes sm_app
        if parsed.path in injected_locations:
            crashed_until = time.time() + CRASH_SECONDS
            tags += ["cve_2025_41452_injected_route_hit", "sm_app_crash"]
            log_request(self, body, tags)
            self._send(502, b"<h1>502 Bad Gateway</h1>", "text/html")
            return

        log_request(self, body, tags)
        self._send(404, b"<h1>404 Not Found</h1>", "text/html")

    do_GET = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_DELETE = _dispatch

    # -- CVE-2025-41450 --------------------------------------------------
    def _handle_getauth(self, body: bytes, params: dict, tags: list):
        fields = {**params, **parse_body(self, body)}
        user = fields.get("username", "")
        password = fields.get("password", "")

        bypass = any(fields.get(attr) == "1" for attr in BYPASS_ATTRIBUTES)
        if bypass:
            tags.append("cve_2025_41450_cotd_attempt")
            expected = generate_code(datetime.now())
            if password == expected:
                token = self._new_session(user or "admin", via="code_of_the_day")
                tags.append("cve_2025_41450_cotd_success")
                log_request(self, body, tags)
                self._send(200, xml_response("ok", f"<session>{token}</session><user>admin</user>"),
                           extra_headers={"Set-Cookie": f"SMSession={token}; path=/"})
                return
            tags.append("cve_2025_41450_cotd_bad_code")
            log_request(self, body, tags)
            self._send(200, xml_response("error", "<error>authentication failed</error>"))
            return

        tags.append("normal_auth")
        if user == ADMIN_USER and password == ADMIN_PASS:
            token = self._new_session(user, via="password")
            log_request(self, body, tags)
            self._send(200, xml_response("ok", f"<session>{token}</session><user>{user}</user>"),
                       extra_headers={"Set-Cookie": f"SMSession={token}; path=/"})
        else:
            log_request(self, body, tags)
            self._send(200, xml_response("error", "<error>authentication failed</error>"))

    def _new_session(self, user: str, via: str) -> str:
        import secrets

        token = secrets.token_hex(16)
        SESSIONS[token] = {"user": user, "via": via, "ts": time.time()}
        return token

    # -- CVE-2025-41451 --------------------------------------------------
    def _handle_set_email_config(self, body: bytes, params: dict, tags: list):
        if not self._session():
            tags.append("unauth_rejected")
            log_request(self, body, tags)
            self._send(200, xml_response("error", "<error>not authenticated</error>"))
            return

        fields = {**params, **parse_body(self, body)}
        # item 0x1be1 = email authentication password (per Claroty writeup)
        smtp_password = fields.get("item_0x1be1", fields.get("smtp_password", ""))

        # vulnerable firmware behavior: value formatted straight into a shell command
        cmd = f"/bin/echo '{smtp_password}' > {STATE}/.smtp_secret"
        tags.append("cve_2025_41451_email_config_save")
        if re.search(r"[;&|`$()<>]", smtp_password):
            tags.append("cve_2025_41451_shell_metachars")
        log_request(self, body, tags + [f"constructed_cmd:{cmd}"])

        proc = subprocess.run(cmd, shell=True, cwd=ROOT, capture_output=True, text=True)
        if proc.returncode == 0:
            self._send(200, xml_response("ok", "<message>email configuration saved</message>"))
        else:
            self._send(200, xml_response("error", "<error>failed to save configuration</error>"))

    # -- CVE-2025-41452 --------------------------------------------------
    def _handle_load_nginx_headers(self, body: bytes, tags: list):
        global injected_locations, injected_headers
        if not self._session():
            tags.append("unauth_rejected")
            log_request(self, body, tags)
            self._send(200, xml_response("error", "<error>not authenticated</error>"))
            return

        ctype = self.headers.get("Content-Type", "")
        conf = ""
        if "multipart/form-data" in ctype:
            boundary = ctype.split("boundary=")[-1].encode()
            for part in body.split(b"--" + boundary):
                if b"filename=" in part:
                    conf = part.split(b"\r\n\r\n", 1)[1].rstrip(b"\r\n-").decode("utf-8", "replace")
                    break
        else:
            conf = body.decode("utf-8", "replace")

        conf_path = STATE / "headers.conf"
        conf_path.write_text(conf)
        injected_locations = re.findall(r"location\s+(?:=\s*)?(/\S*)", conf)
        injected_headers = re.findall(r'add_header\s+([\w-]+)\s+"?([^";]+)"?\s*;', conf)

        tags += ["cve_2025_41452_headers_conf_upload",
                 f"injected_locations:{','.join(injected_locations) or 'none'}",
                 f"injected_headers:{injected_headers or 'none'}"]
        log_request(self, body, tags)
        # firmware reloads the external nginx at runtime
        self._send(200, xml_response("ok", "<message>headers.conf applied, nginx reloaded</message>"))


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = ThreadingHTTPServer(("127.0.0.1", port), AKSMHandler)
    print(f"[emulator] AK-SM 800A (vulnerable, pre-R4.2) on http://127.0.0.1:{port}")
    print(f"[emulator] logging requests to {LOG}")
    print(f"[emulator] legit creds: {ADMIN_USER}:{shlex.quote(ADMIN_PASS)}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
