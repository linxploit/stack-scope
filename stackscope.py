#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 ____ _____  _    ____ _  ______   ____ ___  ____  _____
/ ___|_   _|/ \\  / ___| |/ / ___| / ___/ _ \\|  _ \\| ____|
\\___ \\ | | / _ \\| |   | ' /\\___ \\| |  | | | | |_) |  _|
 ___) || |/ ___ \\ |___| . \\ ___) | |__| |_| |  __/| |___
|____/ |_/_/   \\_\\____|_|\\_\\____/ \\____\\___/|_|   |_____|

StackScope — Web Technology Fingerprinting & CMS Detection
Made by Mindless — Founder & CEO of Linxploit
https://linxploit.com | https://linxploit.com/founder

WHAT THIS TOOL DOES:
    StackScope sends a single, normal HTTP GET request per target — the
    same request any browser makes when loading a page — and matches
    the response headers and HTML against a signature database of web
    servers, frameworks, CMS platforms, analytics/tracking services,
    and CDNs. It also flags version disclosure and known end-of-life
    software versions where a version string is visible.

"""

import argparse
import concurrent.futures
import csv
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

TOOL_NAME = "StackScope"
VERSION = "1.0.0"
AUTHOR = "Mindless"
ORG = "Linxploit"
SITE = "https://linxploit.com"
PORTFOLIO = "https://linxploit.com/founder"

requests.packages.urllib3.disable_warnings()  # noqa


GRADIENT = [
    "\033[38;5;99m", "\033[38;5;105m", "\033[38;5;111m", "\033[38;5;117m",
    "\033[38;5;123m", "\033[38;5;229m", "\033[38;5;222m", "\033[38;5;215m",
    "\033[38;5;208m", "\033[38;5;214m",
]
RESET = Style.RESET_ALL
DIM = Style.DIM
BOLD = Style.BRIGHT

C_OK = Fore.GREEN + BOLD
C_HIGH_CONF = Fore.GREEN
C_MED_CONF = Fore.YELLOW
C_LOW_CONF = Fore.WHITE + DIM
C_WARN = Fore.YELLOW + BOLD
C_BAD = Fore.RED + BOLD
C_MUTE = Fore.WHITE + DIM
C_ACC = "\033[38;5;99m" + BOLD  # indigo accent
C_INFO = Fore.CYAN

CONFIDENCE_COLOR = {"HIGH": C_HIGH_CONF, "MEDIUM": C_MED_CONF, "LOW": C_LOW_CONF}


def supports_unicode() -> bool:
    enc = (sys.stdout.encoding or "").lower()
    return "utf" in enc


UNICODE_OK = supports_unicode()

BOX = {
    "tl": "╔" if UNICODE_OK else "+", "tr": "╗" if UNICODE_OK else "+",
    "bl": "╚" if UNICODE_OK else "+", "br": "╝" if UNICODE_OK else "+",
    "h": "═" if UNICODE_OK else "-", "v": "║" if UNICODE_OK else "|",
    "lt": "╠" if UNICODE_OK else "+", "rt": "╣" if UNICODE_OK else "+",
    "thin": "─" if UNICODE_OK else "-",
    "check": "✔" if UNICODE_OK else "OK", "cross": "✘" if UNICODE_OK else "X",
    "warn": "⚠" if UNICODE_OK else "!", "spark": "✦" if UNICODE_OK else "*",
    "dot": "•" if UNICODE_OK else "*", "mag": "🔍" if UNICODE_OK else "[?]",
    "tree": "├─" if UNICODE_OK else "|-", "treeend": "└─" if UNICODE_OK else "`-",
}

BANNER_ART = r"""
 ____ _____  _    ____ _  ______   ____ ___  ____  _____
/ ___|_   _|/ \  / ___| |/ / ___| / ___/ _ \|  _ \| ____|
\___ \ | | / _ \| |   | ' /\___ \| |  | | | | |_) |  _|
 ___) || |/ ___ \ |___| . \ ___) | |__| |_| |  __/| |___
|____/ |_/_/   \_\____|_|\_\____/ \____\___/|_|   |_____|
""".rstrip("\n")

BANNER_ART_ASCII = r"""
 ____ _____ _   ___ _  __  ___  ___ ___  ___ ___
/ ___|_   _/_\ / __| |/ / / __|/ __/ _ \| _ \ __|
\___ \ | |/ _ \ (__| ' <  \__ \ (_| (_) |  _/ _|
|____/ |_/_/ \_\___|_|\_\ |___/\___\___/|_| |___|
""".rstrip("\n")

import re as _re  # noqa: E402
ANSI_RE = _re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def gradient_line(text: str) -> str:
    out = []
    n = max(len(GRADIENT) - 1, 1)
    for i, ch in enumerate(text):
        color = GRADIENT[int((i / max(len(text) - 1, 1)) * n)]
        out.append(color + ch)
    return "".join(out) + RESET


def render_banner():
    art = BANNER_ART if UNICODE_OK else BANNER_ART_ASCII
    width = max(len(strip_ansi(line)) for line in art.splitlines()) + 6

    print()
    for line in art.splitlines():
        print(gradient_line(line))
    print()

    tagline = f"{BOX['spark']} Web Technology Fingerprinting & CMS Detection {BOX['spark']}"
    print(C_ACC + tagline.center(width) + RESET)
    sub = f"v{VERSION} · Signature-based fingerprinting. No exploitation."
    print(C_MUTE + sub.center(width) + RESET)
    print()
    info_box(
        [
            f"{BOX['dot']} Author   : {AUTHOR}  ({ORG} — Founder & CEO)",
            f"{BOX['dot']} Website  : {SITE}",
            f"{BOX['dot']} Portfolio: {PORTFOLIO}",
        ],
        title="ABOUT",
        color=Fore.MAGENTA,
    )


def info_box(lines: List[str], title: str = "", color: str = Fore.CYAN, width: Optional[int] = None):
    content_width = width or (max((len(strip_ansi(l)) for l in lines), default=20) + 4)
    top = f"{color}{BOX['tl']}{BOX['h'] * content_width}{BOX['tr']}{RESET}"
    bot = f"{color}{BOX['bl']}{BOX['h'] * content_width}{BOX['br']}{RESET}"
    print(top)
    if title:
        pad = content_width - len(title) - 2
        left = pad // 2
        right = pad - left
        print(f"{color}{BOX['v']}{RESET} {' ' * left}{BOLD}{title}{RESET}{' ' * right} {color}{BOX['v']}{RESET}")
        print(f"{color}{BOX['lt']}{BOX['h'] * content_width}{BOX['rt']}{RESET}")
    for line in lines:
        pad = max(content_width - len(strip_ansi(line)) - 1, 0)
        print(f"{color}{BOX['v']}{RESET} {Fore.WHITE}{line}{RESET}{' ' * pad}{color}{BOX['v']}{RESET}")
    print(bot)


def section(title: str, color: str = Fore.CYAN):
    print(f"\n{color}[ {title} ]{RESET}")
    print(color + BOX["thin"] * 60 + RESET)


def hr(color=C_MUTE, width=70):
    print(color + BOX["h"] * width + RESET)

# Every pattern is a real regular expression (fixed from the original, which
# defined regex-looking strings but only ever ran plain substring checks —
# meaning any pattern with a capture group, like a version number, never


SERVER_SIGNATURES = {
    "Apache": [r"Apache(?:/(\d+(?:\.\d+)*))?"],
    "Nginx": [r"nginx(?:/(\d+(?:\.\d+)*))?"],
    "IIS": [r"Microsoft-IIS(?:/(\d+(?:\.\d+)*))?"],
    "Tomcat": [r"Apache-Coyote(?:/(\d+(?:\.\d+)*))?", r"Tomcat"],
    "Jetty": [r"Jetty(?:\((\d+(?:\.\d+)*)\))?"],
    "Caddy": [r"Caddy"],
    "Lighttpd": [r"lighttpd(?:/(\d+(?:\.\d+)*))?"],
    "LiteSpeed": [r"LiteSpeed"],
    "OpenResty": [r"openresty(?:/(\d+(?:\.\d+)*))?"],
    "Gunicorn": [r"gunicorn(?:/(\d+(?:\.\d+)*))?"],
}

FRAMEWORK_SIGNATURES = {
    "PHP": [r"PHP/(\d+(?:\.\d+)*)", r"\.php\b"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Symfony": [r"symfony", r"__symfony"],
    "CodeIgniter": [r"codeigniter", r"ci_session"],
    "Django": [r"csrftoken", r"__django"],
    "Flask": [r"werkzeug", r"flask"],
    "FastAPI": [r"fastapi"],
    "Ruby on Rails": [r"_rails_session", r"X-Runtime"],
    "Spring": [r"X-Application-Context", r"jsessionid"],
    "Next.js": [r"__next", r"_next/static", r"x-powered-by:\s*next\.js"],
    "Nuxt.js": [r"__nuxt", r"_nuxt/"],
    "Gatsby": [r"gatsby"],
    "ASP.NET": [r"ASP\.NET", r"__VIEWSTATE", r"X-AspNet-Version:\s*(\d+(?:\.\d+)*)"],
    "ASP.NET MVC": [r"X-AspNetMvc-Version:\s*(\d+(?:\.\d+)*)"],
}

FRONTEND_LIBRARY_SIGNATURES = {
    "React": [r"react(?:-dom)?[.\-]"],
    "Vue.js": [r"vue(?:\.min)?\.js", r"__vue__"],
    "Angular": [r"ng-version=\"(\d+(?:\.\d+)*)\"", r"angular[.\-]"],
    "jQuery": [r"jquery(?:-|\.)(\d+(?:\.\d+)*)?"],
    "Bootstrap": [r"bootstrap(?:\.min)?\.css", r"bootstrap[.\-](\d+(?:\.\d+)*)"],
    "Tailwind CSS": [r"tailwind"],
}

CMS_SIGNATURES = {
    "WordPress": {
        "headers": [], "html": [r"wp-content", r"wp-includes"],
        "meta": [r'generator"\s*content="WordPress\s*(\d+(?:\.\d+)*)?'],
    },
    "Drupal": {
        "headers": ["X-Drupal-Cache", "X-Drupal-Dynamic-Cache", "X-Generator"],
        "html": [r"drupal\.js", r"sites/default/files"],
        "meta": [r'generator"\s*content="Drupal\s*(\d+)?'],
    },
    "Joomla": {
        "headers": ["X-Joomla-Cache"],
        "html": [r"/media/jui/", r"joomla"],
        "meta": [r'generator"\s*content="Joomla!?\s*(\d+(?:\.\d+)*)?'],
    },
    "Magento": {
        "headers": ["X-Magento-Cache-Debug"],
        "html": [r"magento", r"/skin/frontend/", r"Mage\.Cookies"],
        "meta": [],
    },
    "PrestaShop": {
        "headers": [], "html": [r"prestashop"],
        "meta": [r'generator"\s*content="PrestaShop'],
    },
    "Shopify": {
        "headers": ["X-Shopify-Stage", "X-ShopId"],
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "meta": [],
    },
    "Wix": {
        "headers": ["X-Wix-Request-Id"],
        "html": [r"static\.wixstatic\.com"],
        "meta": [],
    },
    "Squarespace": {
        "headers": [], "html": [r"squarespace\.com", r"static1\.squarespace\.com"],
        "meta": [r'generator"\s*content="Squarespace'],
    },
    "Ghost": {
        "headers": [], "html": [r"ghost\.org", r"content=\"Ghost"],
        "meta": [r'generator"\s*content="Ghost\s*(\d+(?:\.\d+)*)?'],
    },
}

ANALYTICS_SIGNATURES = {
    "Google Analytics": [r"google-analytics\.com", r"gtag\("],
    "Google Tag Manager": [r"googletagmanager\.com"],
    "Facebook Pixel": [r"fbq\(", r"connect\.facebook\.net"],
    "Hotjar": [r"hotjar\.com"],
    "Mixpanel": [r"mixpanel\.com"],
    "Segment": [r"cdn\.segment\.com"],
    "Amplitude": [r"amplitude\.com"],
    "Matomo": [r"matomo\.js", r"piwik\.js"],
    "New Relic": [r"newrelic\.com"],
    "Hubspot": [r"js\.hs-scripts\.com", r"hubspot"],
}

CDN_SIGNATURES = {
    "Cloudflare": [r"cloudflare"],
    "Akamai": [r"akamai"],
    "Fastly": [r"fastly"],
    "AWS CloudFront": [r"cloudfront\.net"],
    "Azure CDN": [r"azureedge\.net"],
    "Google Cloud CDN": [r"gstatic\.com"],
    "StackPath": [r"stackpathcdn\.com"],
    "KeyCDN": [r"kxcdn\.com"],
    "jsDelivr": [r"cdn\.jsdelivr\.net"],
    "cdnjs": [r"cdnjs\.cloudflare\.com"],
}

TECH_INDICATOR_HEADERS = {
    "X-Powered-By": "Framework/Language disclosure",
    "X-Generator": "CMS/Generator disclosure",
    "Via": "Proxy/CDN in path",
    "X-Varnish": "Varnish Cache",
    "X-Cache": "Cache layer",
    "CF-Ray": "Cloudflare",
    "X-CloudFront-ID": "AWS CloudFront",
    "X-Akamai-Transformed": "Akamai",
    "X-Fastly-Request-ID": "Fastly",
}

# End-of-life / outdated version markers — (name, max_eol_version_exclusive)
# Anything at or below these is flagged. Kept intentionally conservative and
EOL_THRESHOLDS = {
    "PHP": (8, 0),
    "Apache": (2, 4),
    "Nginx": (1, 20),
    "IIS": (8, 0),
}

INTERESTING_HEADERS = [
    "Server", "X-Powered-By", "X-Generator", "Via", "CF-Ray", "X-CloudFront-ID",
    "X-Akamai-Transformed", "X-Cache", "Content-Security-Policy", "Permissions-Policy",
]


@dataclass
class Technology:
    category: str
    name: str
    version: Optional[str] = None
    confidence: str = "MEDIUM"
    evidence: str = ""


@dataclass
class ScanResult:
    url: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    response_size: int = 0
    duration_s: float = 0.0
    technologies: List[Technology] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    version_disclosures: List[str] = field(default_factory=list)
    outdated_flags: List[str] = field(default_factory=list)
    error: Optional[str] = None


def _search(patterns: List[str], text: str) -> Optional[re.Match]:
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match
    return None


def _version_from_match(match: re.Match) -> Optional[str]:
    if match and match.groups() and match.group(1):
        return match.group(1)
    return None


def _parse_version_tuple(version: str):
    try:
        return tuple(int(p) for p in version.split(".")[:2])
    except ValueError:
        return None


def detect_server(headers: Dict[str, str]) -> List[Technology]:
    found = []
    server_header = headers.get("Server", "")
    if not server_header:
        return found

    for name, patterns in SERVER_SIGNATURES.items():
        match = _search(patterns, server_header)
        if match:
            version = _version_from_match(match)
            found.append(Technology("Web Server", name, version, "HIGH", f"Server header: {server_header}"))
            return found

    # Unknown server string — still surface it, lower confidence.
    found.append(Technology("Web Server", server_header.split("/")[0], None, "MEDIUM",
                             f"Server header: {server_header}"))
    return found


def detect_frameworks(headers: Dict[str, str], html: str) -> List[Technology]:
    found = []
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())

    for name, patterns in FRAMEWORK_SIGNATURES.items():
        match = _search(patterns, header_blob)
        if match:
            found.append(Technology("Framework", name, _version_from_match(match), "HIGH",
                                     f"Header match: {match.group(0)[:60]}"))
            continue
        match = _search(patterns, html or "")
        if match:
            found.append(Technology("Framework", name, _version_from_match(match), "MEDIUM",
                                     f"HTML match: {match.group(0)[:60]}"))
    return found


def detect_frontend_libraries(html: str) -> List[Technology]:
    found = []
    if not html:
        return found
    for name, patterns in FRONTEND_LIBRARY_SIGNATURES.items():
        match = _search(patterns, html)
        if match:
            found.append(Technology("Frontend Library", name, _version_from_match(match), "MEDIUM",
                                     f"HTML match: {match.group(0)[:60]}"))
    return found


def detect_cms(headers: Dict[str, str], html: str) -> List[Technology]:
    found = []
    html = html or ""
    for name, sig in CMS_SIGNATURES.items():
        for header in sig["headers"]:
            if header in headers:
                found.append(Technology("CMS", name, None, "HIGH", f"Header present: {header}"))
                break
        else:
            match = _search(sig["meta"], html) or _search(sig["html"], html)
            if match:
                confidence = "HIGH" if _search(sig["meta"], html) else "MEDIUM"
                found.append(Technology("CMS", name, _version_from_match(match), confidence,
                                         f"Match: {match.group(0)[:60]}"))
    return found


def detect_analytics(html: str) -> List[Technology]:
    found = []
    if not html:
        return found
    for name, patterns in ANALYTICS_SIGNATURES.items():
        match = _search(patterns, html)
        if match:
            found.append(Technology("Analytics", name, None, "HIGH", f"Reference found: {match.group(0)[:60]}"))
    return found


def detect_cdn(headers: Dict[str, str], html: str) -> List[Technology]:
    found = []
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
    haystacks = [header_blob, html or ""]
    seen = set()
    for name, patterns in CDN_SIGNATURES.items():
        for haystack in haystacks:
            match = _search(patterns, haystack)
            if match and name not in seen:
                found.append(Technology("CDN", name, None, "HIGH", f"Reference found: {match.group(0)[:60]}"))
                seen.add(name)
                break
    return found


def detect_indicator_headers(headers: Dict[str, str]) -> List[Technology]:
    found = []
    for header, label in TECH_INDICATOR_HEADERS.items():
        if header in headers:
            value = headers[header][:60]
            found.append(Technology(label, header, None, "MEDIUM", f"{header}: {value}"))
    return found


def dedupe(technologies: List[Technology]) -> List[Technology]:
    best: Dict[str, Technology] = {}
    rank = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
    for tech in technologies:
        key = f"{tech.category}:{tech.name}"
        if key not in best or rank.get(tech.confidence, 0) > rank.get(best[key].confidence, 0):
            best[key] = tech
        elif key in best and not best[key].version and tech.version:
            best[key].version = tech.version
    return list(best.values())


def check_version_risks(technologies: List[Technology]):
    disclosures = []
    outdated = []
    for tech in technologies:
        if tech.version:
            disclosures.append(f"{tech.name} {tech.version}")
            threshold = EOL_THRESHOLDS.get(tech.name)
            parsed = _parse_version_tuple(tech.version)
            if threshold and parsed and parsed < threshold:
                outdated.append(f"{tech.name} {tech.version} is likely end-of-life "
                                 f"(compare against {threshold[0]}.{threshold[1]}+)")
    return disclosures, outdated


def fetch(url: str, timeout: int, headers: dict, cookies: dict, verify_ssl: bool):
    try:
        return requests.get(url, timeout=timeout, headers=headers, cookies=cookies,
                             verify=verify_ssl, allow_redirects=True), None
    except requests.exceptions.SSLError:
        if url.startswith("https://"):
            try:
                fallback = url.replace("https://", "http://", 1)
                return requests.get(fallback, timeout=timeout, headers=headers, cookies=cookies,
                                     verify=verify_ssl, allow_redirects=True), None
            except Exception as e:  # noqa
                return None, f"SSL error, HTTP fallback also failed: {e}"
        return None, "SSL error"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except requests.exceptions.ConnectionError:
        return None, "Connection failed"
    except Exception as e:  # noqa
        return None, str(e)


def scan_target(url: str, timeout: int, headers: dict, cookies: dict, verify_ssl: bool) -> ScanResult:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    result = ScanResult(url=url)
    start = time.perf_counter()

    resp, error = fetch(url, timeout, headers, cookies, verify_ssl)
    result.duration_s = round(time.perf_counter() - start, 2)

    if error:
        result.error = error
        return result

    result.final_url = resp.url
    result.status_code = resp.status_code
    result.response_size = len(resp.content)
    result.headers = dict(resp.headers)
    html = resp.text

    techs: List[Technology] = []
    techs += detect_server(result.headers)
    techs += detect_frameworks(result.headers, html)
    techs += detect_frontend_libraries(html)
    techs += detect_cms(result.headers, html)
    techs += detect_analytics(html)
    techs += detect_cdn(result.headers, html)
    techs += detect_indicator_headers(result.headers)

    result.technologies = dedupe(techs)
    result.version_disclosures, result.outdated_flags = check_version_risks(result.technologies)

    return result



def print_result(result: ScanResult, verbose: bool):
    section(f"TARGET: {result.url}", Fore.CYAN)

    if result.error:
        print(f"  {C_BAD}{BOX['cross']} {result.error}{RESET}")
        return

    print(f"  {C_MUTE}Status: {result.status_code}   Size: {result.response_size}b   "
          f"Time: {result.duration_s}s{RESET}")
    if result.final_url != result.url:
        print(f"  {C_MUTE}Redirected to: {result.final_url}{RESET}")

    if not result.technologies:
        print(f"\n  {C_WARN}{BOX['warn']} No technologies detected — site may be heavily custom-built or obfuscated.{RESET}")
        return

    by_category: Dict[str, List[Technology]] = {}
    for tech in result.technologies:
        by_category.setdefault(tech.category, []).append(tech)

    print()
    for category in sorted(by_category):
        print(f"  {C_ACC}{category}{RESET}")
        for tech in by_category[category]:
            color = CONFIDENCE_COLOR.get(tech.confidence, C_MUTE)
            version = f" v{tech.version}" if tech.version else ""
            print(f"    {BOX['dot']} {Fore.WHITE}{tech.name}{version}{RESET}  {color}[{tech.confidence}]{RESET}")
            if verbose:
                print(f"      {BOX['treeend']} {C_MUTE}{tech.evidence}{RESET}")

    if result.outdated_flags:
        print(f"\n  {C_BAD}{BOX['warn']} Outdated / end-of-life software detected{RESET}")
        for flag in result.outdated_flags:
            print(f"    {BOX['dot']} {C_BAD}{flag}{RESET}")

    if verbose and result.headers:
        interesting = {h: v for h, v in result.headers.items() if h in INTERESTING_HEADERS}
        if interesting:
            print(f"\n  {C_ACC}Interesting Headers{RESET}")
            for h, v in interesting.items():
                shown = v if len(v) <= 80 else v[:80] + "..."
                print(f"    {BOX['dot']} {h}: {C_INFO}{shown}{RESET}")

    if "X-Powered-By" in result.headers:
        print(f"\n  {C_WARN}{BOX['warn']} Information disclosure via X-Powered-By header ({result.headers['X-Powered-By']}){RESET}")


def print_summary(results: List[ScanResult]):
    section("SCAN SUMMARY", Fore.MAGENTA)
    scanned = [r for r in results if not r.error]
    errored = [r for r in results if r.error]
    outdated = [r for r in scanned if r.outdated_flags]

    print(f"  {BOLD}Targets scanned:{RESET} {len(results)}")
    print(f"  {C_OK}Successfully fingerprinted:{RESET} {len(scanned)}")
    if outdated:
        print(f"  {C_BAD}Targets with outdated/EOL software:{RESET} {len(outdated)}")
    if errored:
        print(f"  {C_MUTE}Targets that could not be reached:{RESET} {len(errored)}")
    print()


def save_json(results: List[ScanResult], path: str):
    data = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "author": AUTHOR,
        "organization": ORG,
        "results": [
            {
                "url": r.url,
                "final_url": r.final_url,
                "status_code": r.status_code,
                "response_size": r.response_size,
                "duration_s": r.duration_s,
                "error": r.error,
                "technologies": [asdict(t) for t in r.technologies],
                "version_disclosures": r.version_disclosures,
                "outdated_flags": r.outdated_flags,
            }
            for r in results
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def save_csv(results: List[ScanResult], path: str):
    fields = ["url", "category", "name", "version", "confidence", "evidence"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            for tech in r.technologies:
                row = asdict(tech)
                row["url"] = r.url
                writer.writerow({k: row.get(k) for k in fields})

def parse_header_list(items: Optional[List[str]]) -> dict:
    headers = {}
    if not items:
        return headers
    for item in items:
        if ":" in item:
            k, v = item.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def parse_cookie_string(cookie_str: Optional[str]) -> dict:
    cookies = {}
    if not cookie_str:
        return cookies
    for part in cookie_str.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def load_targets(args) -> List[str]:
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        if not os.path.isfile(args.list):
            print(C_BAD + f"[!] File not found: {args.list}" + RESET)
            sys.exit(1)
        with open(args.list, "r", encoding="utf-8") as f:
            targets.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))
    return targets


def confirm_authorization(skip: bool) -> bool:
    if skip:
        return True
    print()
    print(f"{C_WARN}{BOX['warn']} StackScope sends one normal GET request per target.{RESET}")
    print(f"{C_WARN}{BOX['warn']} Only assess targets you OWN or are AUTHORIZED to test.{RESET}")
    try:
        answer = input(f"\n{BOLD}Type 'yes' to confirm you are authorized: {RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "yes"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stackscope",
        description=f"{TOOL_NAME} — Web Technology Fingerprinting & CMS Detection by {AUTHOR} ({ORG})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  stackscope.py -u https://example.com\n"
            "  stackscope.py -l targets.txt --threads 5 -v -o report.json\n"
            "  stackscope.py -u example.com --yes --no-banner\n"
        ),
    )
    parser.add_argument("-u", "--url", help="Target URL to fingerprint")
    parser.add_argument("-l", "--list", help="File containing a list of target URLs (one per line)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent targets scanned in parallel (default: 5)")
    parser.add_argument("-H", "--header", action="append", help="Custom header 'Key: Value' (repeatable)")
    parser.add_argument("-b", "--cookies", help="Cookie string 'a=1; b=2'")
    parser.add_argument("--verify-ssl", action="store_true", help="Enable strict SSL certificate verification")
    parser.add_argument("-o", "--output", help="Save results to file (.json or .csv, inferred from extension)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show evidence for every detection and interesting headers")
    parser.add_argument("--yes", action="store_true", help="Skip the authorization confirmation prompt")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    parser.add_argument("--version", action="store_true", help="Show version information and exit")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"{TOOL_NAME} v{VERSION} — by {AUTHOR} ({ORG})")
        return

    if not args.no_banner:
        render_banner()

    targets = load_targets(args)
    if not targets:
        parser.print_help()
        print(C_BAD + "\n[!] No target provided. Use -u/--url or -l/--list.\n" + RESET)
        sys.exit(1)

    if not confirm_authorization(args.yes):
        print(C_BAD + "\n[!] Authorization not confirmed. Aborting.\n" + RESET)
        sys.exit(1)

    headers = parse_header_list(args.header)
    cookies = parse_cookie_string(args.cookies)
    headers.setdefault("User-Agent",
                        f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        f"(KHTML, like Gecko) Chrome/120.0 Safari/537.36 ({TOOL_NAME}/{VERSION})")

    section(f"FINGERPRINTING {len(targets)} TARGET(S)", Fore.CYAN)
    print(f"  {C_MUTE}threads={args.threads}  timeout={args.timeout}s  "
          f"ssl-verify={'on' if args.verify_ssl else 'off'}{RESET}")

    results: List[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(scan_target, url, args.timeout, headers, cookies, args.verify_ssl): url
            for url in targets
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    order = {u: i for i, u in enumerate(targets)}
    results.sort(key=lambda r: order.get(r.url, order.get(r.url.split("://")[-1], 0)))

    for result in results:
        print_result(result, args.verbose)

    print()
    print_summary(results)

    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".csv":
            save_csv(results, args.output)
        else:
            save_json(results, args.output)
        print(C_OK + f"{BOX['check']} Report saved to: {args.output}\n" + RESET)

    hr(C_MUTE, 70)
    print(C_ACC + f"  {TOOL_NAME} · Made by {AUTHOR} — Founder & CEO of {ORG}" + RESET)
    print(C_MUTE + f"  {SITE}  |  {PORTFOLIO}" + RESET)
    hr(C_MUTE, 70)
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(C_WARN + "\n\n[!] Interrupted by user. Exiting.\n" + RESET)
        sys.exit(130)
