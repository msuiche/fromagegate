# Danfoss AK-SM 8xxA — CVE-2025-41450 / -41451 / -41452 PoC toolkit

Research/detection-engineering PoCs for the three AK-SM 8xxA web interface
vulnerabilities disclosed by Claroty Team82 and fixed by Danfoss in R4.2 /
R4.3.1 (DSA-2025-03-01, DSA-2025-08-01, CISA ICSA-25-140-03):

| CVE | Weakness | Affected | Fixed |
|---|---|---|---|
| CVE-2025-41450 | Hidden "code-of-the-day" auth bypass (datetime-derived password) on `xml.cgi?action=getauth` | < R4.2 | R4.2 |
| CVE-2025-41451 | Post-auth OS command injection in alarm-to-mail / SMTP config (item `0x1be1`) | < 4.3.1 | 4.3.1 |
| CVE-2025-41452 | Post-auth nginx `headers.conf` replacement via `action=load_nginx_headers` → directive injection + sm_app crash DoS | < 4.3.1 | 4.3.1 |

## Layout

```
emulator/aksm800a_emulator.py        vulnerable-behavior emulator (127.0.0.1 only)
poc/cve_2025_41450_code_of_the_day.py
poc/cve_2025_41451_alarm_mail_cmd_injection.py
poc/cve_2025_41452_nginx_conf_injection.py
detection/suricata/danfoss-aksm-cves.rules   Suricata rules (see in-file caveats)
detection/sigma/*.yml                        Sigma host/log rules
detection/test_rules_against_captures.py     replay captures against the ruleset
captures/http-requests.jsonl         full request log, tagged per CVE
WRITEUP.md                           FROMAGEGATE incident context + full research summary
```

Python 3 stdlib only; no dependencies.

## Quickstart

```sh
python3 emulator/aksm800a_emulator.py 8080 &          # start the target
python3 poc/cve_2025_41450_code_of_the_day.py         # exit 0 = bypass works
python3 poc/cve_2025_41451_alarm_mail_cmd_injection.py
python3 poc/cve_2025_41452_nginx_conf_injection.py    # add --no-dos to skip DoS
python3 detection/test_rules_against_captures.py      # replay captures vs Suricata rules
```

The 41451 and 41452 PoCs chain through the 41450 bypass by default (a real
attacker has no configured credentials); both accept `--user/--password`
(41451) to start from a legit session instead. All PoCs accept `--target
HOST:PORT`, so they also work against real vulnerable firmware — but the
code-of-the-day algorithm and bypass attribute names must be replaced with
the values recovered from firmware (see caveats below).

## Observable artifacts for detection signatures

Each emulator request is logged to `captures/http-requests.jsonl` with
tags. The stable, signature-worthy network artifacts are:

**CVE-2025-41450 (auth bypass)**
- `POST /xml.cgi?action=getauth` carrying unexpected attributes beyond
  username/password (here: `codeofday=1` / `support=1`; real names are
  redacted in public sources — recover from firmware for final rules).
- Password field containing a short date-derived numeric code rather than
  a real password; successful response issues a session despite no valid
  configured credential. Temporal correlation: code changes daily.
- Version exposure: any AK-SM 8xxA fingerprint (StoreView/AK-SM banner,
  `Server: nginx` on the management port) on firmware < R4.2 is inherently
  vulnerable — banner/version detection is the highest-fidelity signal.

**CVE-2025-41451 (command injection → RCE)**
- Authenticated `POST /xml.cgi?action=set_email_config` with shell
  metacharacters (`; | & $() ` `` ` ``) in the email password field
  (config item `0x1be1`). Legit SMTP passwords rarely contain `;`+command.
- Payload shape: `x'; <cmd> #` / `$(<cmd>)` etc. — see the tagged
  `constructed_cmd:` log lines for exactly how the value lands in a shell.
- Post-exploitation host telemetry: the config-save process spawning
  unexpected child processes (shell, `id`, `curl`, ...).

**CVE-2025-41452 (nginx config injection → traffic manipulation / DoS)**
- Authenticated multipart upload to `xml.cgi?action=load_nginx_headers`
  (filename `headers.conf`). This endpoint has no benign reason to be
  called outside rare admin maintenance — volume-based alerting works.
- Uploaded content containing `location`, `proxy_pass`, `rewrite`,
  `add_header` directives.
- Follow-on: responses carrying attacker-injected headers, and a 502
  followed by a window of 503s when an injected route is hit (sm_app
  crash → repeatable DoS).

## Caveats / provenance

- Claroty redacted the code-of-the-day **attribute names** and the
  **generation algorithm**; this toolkit ships a stand-in algorithm
  (`emulator/aksm800a_emulator.py:generate_code`) that preserves the
  documented property (code derived solely from device date). PoCs and
  emulator share it, so the chain is functional end-to-end. For real
  hardware, extract `check_code_of_day` from firmware and drop it in.
- Request schema (XML field names, action names, session cookie name) is a
  faithful reconstruction from the public writeups, not byte-exact firmware
  behavior. Tune final signatures against traffic from real firmware or a
  recovered request sample.
- The emulator executes the injected 41451 shell payload locally (that's
  the point of the PoC). Default payload is benign (`id` → proof file).
  Bind/run on 127.0.0.1 only.

## References

- Claroty Team82 research: <https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers>
- Danfoss DSA-2025-03-01 (CVE-2025-41450): <https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-03-01/>
- Danfoss DSA-2025-08-01 (CVE-2025-41451, CVE-2025-41452): <https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-08-01/>
- CISA ICSA-25-140-03: <https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03>
