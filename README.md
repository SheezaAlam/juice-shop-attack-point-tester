# 🧃 OWASP Juice Shop — Automated Attack-Point Tester

A lightweight Python tool that automates security testing against three attack points on an authorized OWASP Juice Shop instance: directory-listing exposure, public file access, and HTTP security headers. Built as part of a hands-on cybersecurity automation exercise — turning a manual testing workflow into a repeatable one.

![Python](https://img.shields.io/badge/Python-3-blue?logo=python&logoColor=white)
![Requests](https://img.shields.io/badge/requests-2.34-green)
![Status](https://img.shields.io/badge/status-lab%20prototype-yellow)
![License](https://img.shields.io/badge/scope-authorized%20testing%20only-red)

---

## 🔍 What it does

The tool accepts a target URL, runs three non-destructive checks against it, analyzes each response, flags anything that merits manual review, and saves a timestamped report — all in one run.

| Test | Target | Checks for |
|---|---|---|
| **1. Directory listing** | `GET /ftp/` | Known file-name indicators exposed in the response body |
| **2. Public file access** | `GET /ftp/acquisitions.md` | Whether a specific resource is reachable without authentication |
| **3. Security headers** | `GET /` | `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, and `Strict-Transport-Security` (HTTPS only) |

Each result is classified as `POTENTIAL FINDING`, `REVIEW REQUIRED`, `NOT DETECTED`/`NOT FOUND`, `INCONCLUSIVE`, or `TEST ERROR` — automated triage signals, not confirmed vulnerabilities.

---

## 📸 In action

**Setup — virtual environment and dependencies**

![Environment setup](juice-shop-attack-point-tester/screenshots/01_environment_setup.png)

**Connectivity check against the target**

![Connectivity check](juice-shop-attack-point-tester/screenshots/02_connectivity_check.png)

**All three tests running end to end**

![Full test run](juice-shop-attack-point-tester/screenshots/05_all_three_tests_summary.png)

**Generated report, saved and verified on disk**

![Report saved](juice-shop-attack-point-tester/screenshots/11_report_saved_verified.png)

More screenshots are available in [`juice-shop-attack-point-tester/screenshots/`](screenshots/), and raw run output in [`juice-shop-attack-point-tester/evidence/`](evidence/) and [`juice-shop-attack-point-tester/reports/`](reports/).

---

## ⚙️ Installation

```bash
git clone <this-repo-url>
cd juice-shop-attack-tester

python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install requests
```

**Requirements:** Python 3, the `requests` package, and network access to your own authorized Juice Shop instance.

## ▶️ Usage

```bash
python juice_shop_tester.py
```

You'll be prompted for the base URL of your lab instance, e.g.:

```
Enter your authorized lab URL: http://192.168.52.1:3000
```

The tool prints results live to the terminal and saves a timestamped report under `reports/`.

To also capture the full terminal transcript:

```bash
python juice_shop_tester.py | tee reports/run_log.txt
```

## 🧾 Result labels

| Label | Meaning |
|---|---|
| `POTENTIAL FINDING` | Configured directory/file indicators were found |
| `REVIEW REQUIRED` | Resource returned HTTP 200, or a configured security header was missing |
| `NOT DETECTED` / `NOT FOUND` | No indicators found, or resource returned HTTP 404 |
| `INCONCLUSIVE` | Response didn't match the configured basic conditions |
| `TEST ERROR` | The request itself failed (timeout, connection error, etc.) |

> These are triage signals, not proof of a vulnerability — every flagged item needs manual verification.

## 🗂️ Project structure

```
.
├── juice_shop_tester.py              # The tool itself
├── Security_Testing_Report.md        # Full write-up: methodology, results, evidence, recommendations
├── testing_methodology.md            # Per-attack-point methodology
├── limitations_and_improvements.md   # Known limitations and roadmap
├── evidence/                         # Raw observed terminal output
├── reports/                          # Generated/observed test reports
└── screenshots/                      # Evidence screenshots from the lab run
```

## 🧠 Why these three attack points

These were chosen from a Week 1 attack-surface mapping of Juice Shop because they're externally reachable without credentials, require no destructive payloads, and reflect findings a SOC/AppSec analyst actually triages day-to-day: information disclosure and missing hardening headers.

## 🚧 Limitations

- Three fixed checks only — this is a focused prototype, not a general-purpose scanner.
- Directory-listing detection relies on known indicator strings.
- HTTP 200 alone doesn't prove a resource was meant to be private.
- No authentication, crawling, or role-based access testing — by design, non-destructive scope only.

See [`limitations_and_improvements.md`](limitations_and_improvements.md) for the full list and planned improvements (CLI flags, JSON/CSV output, unit tests, allowlisting).

## ⚠️ Authorization

**Only run this tool against your own Juice Shop instance or systems you have explicit, written authorization to test.** This project was built and tested exclusively against a local, isolated lab deployment.

## 👩‍💻 Author

Sheeza Alam Khan — Cybersecurity Analyst (SOC & Threat Detection)
