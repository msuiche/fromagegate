# FROMAGEGATE

## Detection-engineering writeup: the October 2026 French supermarket refrigeration attack and the Danfoss AK-SM 8xxA CVEs (CVE-2025-41450 / CVE-2025-41451 / CVE-2025-41452)

> **FROMAGEGATE** is the tracking name this research assigns to the October 11–12, 2026 campaign against French supermarket refrigeration. It is a researcher-assigned codename, not an official designation by Danfoss, ANSSI, or any vendor.

## 1. The incident

Hackers exploited vulnerabilities in Danfoss refrigeration controllers with outdated firmware to remotely trigger defrost cycles and raise temperatures to 50°C in hundreds of French supermarkets overnight, spoiling food worth millions of euros and causing small fires.

Major chains affected include Intermarché (around 150 stores), Coopérative U (nearly 100), Carrefour (80 stores), and Monoprix, with some impacts also reported in Spain, Portugal, Poland, Germany, and Belgium.

The incident underscores risks of internet-connected industrial IoT devices in food supply chains, prompting investigations by French prosecutors and the national cybersecurity agency ANSSI.

### Scale

Primarily France, with hundreds of stores affected (estimates commonly around 250–400+, up to roughly 500 in some aggregations); reports also mention possible impacts in several other European countries, though those are less confirmed and lack detailed store counts.

FROMAGEGATE mainly hit French supermarkets overnight on October 11–12, 2026, targeting outdated Danfoss refrigeration controllers. Reported figures vary by source and retailer:

- **Intermarché and Netto** (Groupement Mousquetaires): ~150 to 300 stores (higher figures from BFMTV and some AFP/Le Figaro reports; lower ones from the chain or early statements).
- **Coopérative U**: roughly 100 or fewer than 100.
- **Carrefour**: 80 stores (out of ~6,000).
- **Monoprix**: about 5% of its ~400–490 French stores (~20–30).
- **E.Leclerc**: some stores affected (no precise number confirmed publicly).

Overall totals cited in reporting include about 250–350 (e.g., BleepingComputer citing French outlets), around 400 (BBC, based on chain figures out of ~15,000 French stores total), or higher aggregates near 500 when combining all named chains. Losses involved spoiled fresh/frozen food worth millions of euros in total, with some local examples in the hundreds of thousands of euros per store or pair of stores, plus isolated small fires.

### Countries

The large-scale, confirmed impacts are in **France**. A Sekoia threat analyst (Felix Aimé) stated that Spain, Portugal, Poland, Germany, and Belgium had also been affected; this is referenced in Reuters and other coverage, and French authorities (including ANSSI) coordinated with European counterparts due to the shared risk of similar Danfoss systems. However, these non-French impacts lack detailed public confirmation of store numbers or the same scale, and at least one Belgian industry source indicated no refrigeration issues there. A separate cybersecurity incident affecting Ahold Delhaize (Netherlands/Belgium and some US operations) was reported around the same time but is not linked to FROMAGEGATE.

In short: hundreds of shops, overwhelmingly in France (with ~400 as a frequently cited ballpark), and reported or potential involvement of up to about 6 European countries total, though only France has clear, quantified large-scale effects so far. Numbers can evolve as investigations continue.

### Which vulnerability was used? Suspected, not confirmed

**No source — not Danfoss, not ANSSI, not the retailers, not the prosecutor — has named the flaw exploited in FROMAGEGATE.** The link to CVE-2025-41450/-41451/-41452 is inference, not reporting:

- Le Parisien reported only that attackers exploited a vulnerability "documented this summer and unpatched" in old software versions.
- Danfoss told AFP that most of the affected equipment was **"legacy" products that "no longer receive software or security updates"** — a statement that may point at the *older AK-SM 800 generation* (already abused in 2022) rather than the AK-SM 8xxA line these CVEs cover.
- BleepingComputer noted explicitly that "no information is available on how the Danfoss refrigeration controllers were compromised."

The three CVEs are nonetheless the prime suspects: they are the only recently documented, remotely exploitable flaws in this product family, the full Team82 writeup dropped two months before the attack, and thousands of unpatched 8xxA interfaces are internet-exposed. This toolkit therefore treats them as the *likely* FROMAGEGATE TTP set to build detection for — while the writeup deliberately avoids asserting they were the actual intrusion vector. If Danfoss or ANSSI later attributes the attack to a different (e.g., legacy AK-SM 800) flaw, the network rules below should be re-scoped accordingly.

## 2. The platform

The **Danfoss AK-SM 800A** is a centralized system manager for commercial refrigeration: it aggregates field controllers and exposes a web management interface ("StoreView") for monitoring temperatures, configuring thresholds and defrost schedules, managing alarms/notifications, users, and maintenance. Technicians administer it remotely, which is why so many instances end up internet-facing — Claroty Team82 counted ~2,765 exposed devices on Censys. Its predecessor, the AK-SM 800, was already abused in 2022 attacks; the 8xxA line is the current generation.

Relevant web-service internals (per Team82's firmware reverse engineering):

```
client → external nginx (internet-facing)
       → sm_fcgi_app (.cgi requests, per sm_fcgi_app.conf)
       → forward_xml_request → internal nginx (loopback)
       → Task_Web in sm_app (core application logic)
```

Notably, the external nginx config **includes `headers.conf`**, and the application can replace that file and reload nginx at runtime — the root of CVE-2025-41452.

## 3. The vulnerabilities

| CVE | CVSS | Weakness | Affected | Fixed |
|---|---|---|---|---|
| CVE-2025-41450 | 8.2 | Hidden "code-of-the-day" authentication bypass — a datetime-derived password accepted by `xml.cgi?action=getauth` when specific request attributes are set (CWE-287/CWE-305) | < R4.2 | R4.2 |
| CVE-2025-41451 | 8.7 | Post-auth OS command injection: the alarm-to-mail / SMTP email password (config item `0x1be1`) is formatted into a shell command unsanitized (CWE-77) | < 4.3.1 | 4.3.1 |
| CVE-2025-41452 | 6.8 (v4) / 5.4 (v3.1) | Post-auth nginx config injection: `action=load_nginx_headers` replaces `headers.conf` (included by the internet-facing nginx); injected routes crash `sm_app` → repeatable DoS (CWE-15) | < 4.3.1 | 4.3.1 |

Key mechanics:

- **CVE-2025-41450** — `check_code_of_day` generates a daily password derived *solely from the device date*. Setting the (redacted) request attributes to `1` routes authentication to this function instead of the configured-password check, yielding a full admin session. Team82 reconstructed the algorithm from firmware but did not publish it, along with the attribute names.
- **CVE-2025-41451** — the SMTP email configuration save handler builds an OS shell command with the value of item `0x1be1` (the email authentication password) without sanitization. Shell metacharacters in that field execute arbitrary commands as the web service user.
- **CVE-2025-41452** — an authenticated multipart upload to `action=load_nginx_headers` replaces `headers.conf` and reloads the external nginx. Arbitrary directives (`add_header`, `location`, `proxy_pass`, rewrites) become live on the management interface; hitting an injected route triggers an unhandled exception in `sm_app`, killing the web service until restart.

## 4. Attack chain (as reconstructed in this toolkit)

1. Recon: find StoreView/AK-SM banner on the internet (thousands exposed).
2. **Bypass auth** with the code-of-the-day (CVE-2025-41450) — no credentials needed on firmware < R4.2.
3. **RCE** via alarm-to-mail command injection (CVE-2025-41451) — full control of the controller OS.
4. Optional: **implant nginx directives** for persistence/traffic manipulation, or crash the web service for DoS (CVE-2025-41452).
5. Operational impact: with control of the system manager, attackers manipulate refrigeration parameters — in FROMAGEGATE the confirmed effect was forced defrost cycles pushing temperatures toward 50°C overnight (via whatever entry vector; see §1 caveat).

## 5. PoC toolkit (this repository)

Python 3 stdlib only. The emulator reproduces the documented vulnerable
behaviors; the PoCs exploit them end-to-end and log every request.

```
emulator/aksm800a_emulator.py        vulnerable-behavior emulator (127.0.0.1:8080)
poc/cve_2025_41450_code_of_the_day.py        auth bypass → admin session
poc/cve_2025_41451_alarm_mail_cmd_injection.py   chained CotD auth → RCE proof
poc/cve_2025_41452_nginx_conf_injection.py   chained CotD auth → directive injection + DoS
detection/suricata/danfoss-aksm-cves.rules   9 rules (7 request-side, 2 response-side)
detection/sigma/*.yml                        4 host/log rules
detection/test_rules_against_captures.py     replays captures against the ruleset
captures/http-requests.jsonl                 tagged request log from PoC runs
```

Run:

```sh
python3 emulator/aksm800a_emulator.py 8080 &
python3 poc/cve_2025_41450_code_of_the_day.py
python3 poc/cve_2025_41451_alarm_mail_cmd_injection.py
python3 poc/cve_2025_41452_nginx_conf_injection.py   # --no-dos to skip the crash
python3 detection/test_rules_against_captures.py     # validate rules vs captures
```

### Verification results (October 12, 2026, local run)

- CVE-2025-41450: wrong password rejected; CotD request (`codeofday=1`, `support=1`, 6-digit code) returned an admin session token. **Exit 0.**
- CVE-2025-41451: payload `x'; id > captures/rce_proof_41451.txt #` in item `0x1be1` executed server-side; proof file contained `uid=501(msuiche) ...`. **Exit 0.**
- CVE-2025-41452: `headers.conf` upload accepted; `X-PoC-41452: injected-always` present on subsequent responses; GET on the injected route → 502, followed by service-wide 503 (sm_app crash DoS). **Exit 0.**
- Rule replay: all 7 request-side Suricata rules fire on the PoC captures; no false positives on a baseline wrong-password auth; all PCREs compile. The 2 response-side rules (503 burst, StoreView banner) are structure-checked only — validate with `suricata -T` and a pcap replay in the lab. Sigma files pass structural checks (no sigma-cli available locally).

## 6. Detection guidance

Highest-fidelity signals for the suspected FROMAGEGATE TTP set, in order:

1. **Firmware version exposure.** Any internet-reachable AK-SM 8xxA below R4.2/4.3.1 is vulnerable by definition — banner/version detection (sid 4414530, Censys/Shodan hygiene) beats behavioral detection.
2. **`action=load_nginx_headers` calls** (sid 4414520/4414521). Essentially no benign volume outside rare maintenance; alert every time.
3. **Shell metacharacters in item `0x1be1`** (sid 4414510, generic variant 4414511). `0x1be1` is documented; the URL-encoded payload shapes (`%27`, `%3b`, `$()`, backtick + command name) are reliable.
4. **getauth anomalies** (sid 4414500 hunting baseline; 4414501 PoC attributes; 4414502 numeric-password heuristic). The definitive bypass attributes are redacted publicly — recover them from firmware to finalize 4414501.
5. **Host side**: web service (`sm_app`/`sm_fcgi_app`) spawning shells/utilities (Sigma, critical); `headers.conf` file modification and web-service-triggered `nginx -s reload` (Sigma, high/medium); 502→503 crash windows (sid 4414522).

## 7. Provenance and limitations

- Technical details come from the public [Claroty Team82 writeup](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers), Danfoss advisories [DSA-2025-03-01](https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-03-01/) and [DSA-2025-08-01](https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-08-01/), and [CISA ICSA-25-140-03](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03).
- FROMAGEGATE is a researcher-assigned tracking name used within this repository; it carries no attribution and is not an official designation.
- No public attribution or confirmed intrusion vector for FROMAGEGATE exists (see §1 caveat). Danfoss's "legacy products, no longer receiving updates" statement to AFP leaves open the possibility that older AK-SM 800 hardware — not the 8xxA line covered here — carried the attack. This writeup covers the three documented CVEs as the suspected TTP set, not as confirmed fact.
- Team82 **redacted** the code-of-the-day attribute names and the generation algorithm. This toolkit ships a stand-in algorithm preserving the documented property (date-only-derived code); PoCs and emulator share it, so the chain is functional end-to-end. For real firmware, extract `check_code_of_day` and the real attribute names and drop them in.
- Request schemas (XML field names, session cookie name) are faithful reconstructions, not byte-exact firmware behavior. Tune rules against real firmware traffic before production deployment.

## 8. Recommendations

### 8.1 Patch — and verify the patch actually landed

- Upgrade every AK-SM 8xxA to **R4.3.1 or later**. Note the version split: **R4.2 fixes only the code-of-the-day bypass** (CVE-2025-41450); the RCE and nginx injection (CVE-2025-41451/-41452) require **R4.3.1**. A fleet sitting at R4.2.x is still remotely exploitable post-auth.
- Don't trust the update queue: pull a firmware-version inventory from every unit after patching and reconcile it against the install base. FROMAGEGATE hit organizations that presumably "had a patch process."
- **Legacy AK-SM 800 units cannot be patched** — they no longer receive updates (per Danfoss's own AFP statement). There is no fix coming; plan replacement, and until then treat every such unit as permanently compromised-able and apply §8.2 strictly.

### 8.2 Get those interfaces off the internet — this is the big one

Patching alone would not have prevented a FROMAGEGATE-scale event; **exposure did the damage**. ~2,765 StoreView management interfaces were visible on Censys before the attack. None of them should have been reachable from the internet at all. Danfoss's own guidance (DSA-2025-08-01 mitigation note) and Claroty's disclosure both say the same: management interfaces belong on trusted management networks, behind VPNs, not on the public internet.

- **Zero public exposure**: the StoreView/web management interface must never answer on a public IP. No port-forwarding on store routers, no UPnP, no "temporary" NAT rules that become permanent.
- **Segment**: put refrigeration supervision on a dedicated OT VLAN with no route to/from the internet and tightly controlled east-west access from the corporate network.
- **Remote access via a brokered path only**: the telemaintenance use case (fridge contractors dialing in) is why these interfaces get exposed — serve it with a VPN concentrator or jump host with MFA and per-contractor IP allowlisting, never by publishing the device.
- **Verify from the outside, continuously**: scan your own perimeter and monitor Censys/Shodan for your ASNs and the StoreView banner (sid 4414530 in the ruleset does this on the wire). Assume that what you can find, an attacker already has.
- **Alert on drift**: any new public listener matching the AK-SM fingerprint should page someone, not land in a monthly report.

### 8.3 Detect and hunt

- Deploy the rules in `detection/`; hunt retrospectively for `load_nginx_headers` calls, getauth anomalies, and 502→503 crash windows.
- Prioritize the high-confidence signals: `action=load_nginx_headers` (sid 4414520/4414521) and shell metacharacters in item `0x1be1` (sid 4414510).

### 8.4 Audit the installed base

Exposure counts in the thousands mean a FROMAGEGATE-scale repeat remains likely. If you operate food retail, cold storage, or logistics: find every Danfoss supervisory controller you own — including the ones the HVAC contractor installed and never told IT about — and run 8.1–8.3 against all of them.

## 9. Timeline

| Date | Event |
|---|---|
| 2025-03-24 | Danfoss DSA-2025-03-01 published (CVE-2025-41450), fix in R4.2 |
| 2025-05-20 | CISA ICSA-25-140-03 published |
| 2025-08-01 | Danfoss DSA-2025-08-01 published (CVE-2025-41451, CVE-2025-41452), fix in R4.3.1 |
| 2025-08-26/27 | CISA ICS advisory covering CVE-2025-41451/-41452 |
| 2026-08-09 | Claroty Team82 full technical writeup ("Freeze the Controller, Defrost the Food") |
| 2026-10-11/12 | **FROMAGEGATE**: overnight attack on French supermarket refrigeration; ~250–400+ stores, food spoilage, small fires; ANSSI and prosecutors investigate; exploited flaw never officially named |
| 2026-10-12/13 | Danfoss tells AFP most affected equipment was "legacy" products no longer receiving software or security updates |

## 10. References

- [Claroty Team82 — Freeze the Controller, Defrost the Food](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [Danfoss DSA-2025-03-01 (CVE-2025-41450)](https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-03-01/)
- [Danfoss DSA-2025-08-01 (CVE-2025-41451, CVE-2025-41452)](https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-08-01/)
- [CISA ICSA-25-140-03](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03)
- [BleepingComputer — Cyberattack shuts down refrigerators at French supermarkets](https://www.bleepingcomputer.com/news/security/cyberattack-shuts-down-refrigerators-at-french-supermarkets/)
- [CBS News/AFP — Danfoss "legacy products" statement](https://www.cbsnews.com/news/cyberattack-supermarkets-refrigerators-france-fires-food-losses/)
- [Reuters — Intermarché cyberattack coverage](https://www.reuters.com/business/retail-consumer/french-supermarket-chain-intermarche-hit-by-cyberattack-150-stories-targeted-2026-10-12/)
- [BBC — French supermarket refrigeration attack](https://www.bbc.co.uk/news/articles/crq5nzxv9q4yo)
- [BFMTV — au moins 300 supermarchés touchés](https://www.bfmtv.com/economie/entreprises/au-moins-300-supermarches-touches-un-systeme-danois-vise-ce-que-l-on-sait-des-cyberattaques-qui-ont-frappe-les-systemes-frigorifiques-des-supermarches_AV-202610120616.html)
