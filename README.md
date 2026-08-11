<div align="center">

```
 ____ _____  _    ____ _  ______   ____ ___  ____  _____
/ ___|_   _|/ \  / ___| |/ / ___| / ___/ _ \|  _ \| ____|
\___\| | / _ \| |   | ' /\___ \| |  | | | | |_) |  _|
 ___)|| |/ ___ \ |___| . \ ___) | |__| |_| |  __/| |___
|____/ |_/_/   \_\____|_|\_\____/ \____\___/|_|   |_____|
```

### Web Technology Fingerprinting & CMS Detection

**Signature-based fingerprinting. No exploitation.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Made by Mindless](https://img.shields.io/badge/Made%20by-Mindless-ff69b4.svg)](https://linxploit.com/founder)
[![Linxploit](https://img.shields.io/badge/Linxploit-linxploit.com-black.svg)](https://linxploit.com)

**Made by [Mindless](https://linxploit.com/founder) — Founder & CEO of [Linxploit](https://linxploit.com)**

</div>

---

## 🧠 What is StackScope?

**StackScope** sends a single, normal HTTP request to a target — the same request a browser makes — and matches the response headers and HTML against a signature database covering web servers, backend frameworks, frontend libraries, CMS platforms, analytics/tracking services, and CDNs.

Where it goes further than a simple keyword grep: every signature is a real, tested regular expression, including version-capturing groups, so StackScope tells you not just *"this runs PHP"* but *"this runs PHP 7.2.24"* — and flags it if that version is past end-of-life.

---

## ✨ Features

- 🎨 **Clean categorized output** — technologies grouped by type (Web Server, Framework, CMS, Frontend Library, Analytics, CDN), each with a confidence rating and evidence trail.
- 🎯 **Real regex-based signatures with version extraction** — servers, frameworks, and CMSs are matched with proper patterns and capture groups, not naive substring checks (a real bug in a lot of simple fingerprinting scripts, including the internal tool this one replaced).
- 📚 **A broad, current signature set**: 10+ web servers, 15+ backend frameworks, 9 CMS platforms (with version detection where the generator meta tag reveals it), 6 frontend libraries, 10 analytics/tracking services, 10 CDNs.
- ⚠️ **End-of-life version flagging** — PHP, Apache, Nginx, and IIS versions are checked against conservative EOL thresholds and called out clearly.
- 🔍 **Information-disclosure awareness** — flags `X-Powered-By` and similar headers that leak stack details regardless of whether the version itself is outdated.
- 🧩 **Smart deduplication** — the same technology detected via multiple signals (header + HTML) is merged into a single entry, keeping the highest-confidence evidence and filling in a version number wherever one is found.
- ⚡ **Concurrent multi-target scanning**, custom headers/cookies for authenticated pages, automatic HTTPS→HTTP fallback on SSL errors.
- 📊 **Exportable reports** — full **JSON** (every technology + evidence) or flat **CSV**.
- 🛡️ **Authorization gate** — confirms you're allowed to assess a target before sending a request (skippable with `--yes`).

---

## 📸 Preview

```
✦ Web Technology Fingerprinting & CMS Detection ✦
v1.0.0 · Signature-based fingerprinting. No exploitation.

[ TARGET: https://example.com ]
────────────────────────────────────────────────────────────
  Status: 200   Size: 336b   Time: 0.18s

  Analytics
    • Google Tag Manager  [HIGH]
  CMS
    • WordPress v6.2  [HIGH]
  Framework
    • PHP v7.2.24  [HIGH]
  Web Server
    • Apache v2.4.29  [HIGH]

  ⚠ Outdated / end-of-life software detected
    • PHP 7.2.24 is likely end-of-life (compare against 8.0+)

  ⚠ Information disclosure via X-Powered-By header (PHP/7.2.24)
```

---

## 📦 Installation

```bash
git clone https://github.com/linxploit/stack-scope.git
cd stack-scope
pip install -r requirements.txt
```

Requires **Python 3.8+**.

---

## 🚀 Usage

### Fingerprint a single site

```bash
python3 stackscope.py -u "https://example.com"
```

### Fingerprint a list of targets

```bash
python3 stackscope.py -l examples/targets.txt --threads 5
```

### See the evidence behind every detection

```bash
python3 stackscope.py -u "https://example.com" -v
```

### Fingerprint an authenticated page

```bash
python3 stackscope.py -u "https://example.com/dashboard" -b "session=abc123"
```

### Save a report

```bash
python3 stackscope.py -l examples/targets.txt -o report.json
python3 stackscope.py -l examples/targets.txt -o report.csv
```

### Skip the authorization prompt (for your own automated pipelines)

```bash
python3 stackscope.py -u "https://example.com" --yes
```

### Full option reference

```bash
python3 stackscope.py --help
```

| Flag | Description |
|---|---|
| `-u`, `--url` | Single target URL |
| `-l`, `--list` | File with one target URL per line |
| `-t`, `--timeout` | Request timeout in seconds (default: `15`) |
| `--threads` | Concurrent targets scanned in parallel (default: `5`) |
| `-H`, `--header` | Custom header `"Key: Value"`, repeatable |
| `-b`, `--cookies` | Cookie string `"a=1; b=2"` |
| `--verify-ssl` | Enable strict SSL certificate verification (off by default) |
| `-o`, `--output` | Save report to `.json` or `.csv` |
| `-v`, `--verbose` | Show evidence for every detection and interesting headers |
| `--yes` | Skip the authorization confirmation prompt |
| `--no-banner` | Suppress the ASCII banner |
| `--version` | Print version info and exit |

---

## 🧭 Confidence levels

| Confidence | Meaning |
|---|---|
| **HIGH** | Matched a distinctive header, cookie, or meta-generator tag specific to that technology. |
| **MEDIUM** | Matched a pattern in the HTML body (script paths, class names, comments) — usually reliable, occasionally coincidental. |
| **LOW** | Reserved for weak/ambiguous signals not currently used by the default signature set. |

> ⚠️ **A detection is a fingerprint, not a guarantee.** Sites can proxy, mask, or spoof headers. Cross-check anything decision-critical manually.

---

## ⚖️ Responsible use

StackScope performs a single, ordinary GET request per target — nothing more than a browser does when loading a page. Still:

- Only run StackScope against targets you **own** or have **explicit permission** to assess.
- StackScope will ask you to confirm authorization before scanning, every time, unless you pass `--yes`.
- You are solely responsible for how you use this tool and for complying with all applicable laws and the terms of any authorization you've been granted.

---

## 🛠️ Project structure

```
stack-scope/
├── stackscope.py           # Main executable — the tool itself
├── requirements.txt          # Python dependencies
├── examples/
│   └── targets.txt              # Example target list for -l/--list
├── tests/
│   └── test_stackscope.py       # Unit tests for the detection engine
├── LICENSE                    # MIT License
└── README.md                   # You are here
```

---

## 🤝 Contributing

Issues and pull requests are welcome — new signatures, updated EOL thresholds, and additional frontend/backend framework coverage are all great contributions.

---

## 📜 License

Released under the [MIT License](LICENSE).

---

<div align="center">

### Made by **Mindless**
**Founder & CEO of [Linxploit](https://linxploit.com)**

🌐 [linxploit.com](https://linxploit.com) &nbsp;·&nbsp; 👤 [linxploit.com/founder](https://linxploit.com/founder)

</div>
