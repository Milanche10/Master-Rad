"""
modules/browser.py
──────────────────
Analiza Chrome browser artefakata:
  - History baza → poseteni URL-ovi i pretrage
  - Login Data → sačuvani korisnički nalozi i lozinke
  - Cookies → aktivne sesije
  - Web Data → sačuvane forme i autofill podaci

Napomena: Chrome koristi Chromium timestamp (mikrosekunde od 1601-01-01).
"""

import re
from collections import defaultdict
from utils.dump_resolver import DumpResolver
from utils.db_reader import SafeDBReader
from utils.helpers import (
    artifact, finding, module_result, not_found_result,
    chrome_time_to_iso,
)

# URL kategorije za klasifikaciju
CATEGORY_PATTERNS = {
    "P2P crypto exchange": [
        r'localbitcoins', r'paxful', r'hodlhodl', r'bisq', r'agoradesk',
    ],
    "Crypto exchange": [
        r'binance', r'coinbase', r'kraken', r'bitfinex', r'huobi', r'kucoin',
        r'bestchange', r'exchangerates',
    ],
    "Crypto wallet": [
        r'etherscan', r'blockchain\.com', r'blockchair', r'blockexplorer',
        r'bscscan', r'tronscan',
    ],
    "VPN / Anonymization": [
        r'nordvpn', r'expressvpn', r'protonvpn', r'torproject', r'mullvad',
        r'privateinternetaccess',
    ],
    "Travel / Booking": [
        r'booking\.com', r'airbnb', r'hotels\.com', r'expedia', r'kayak',
        r'skyscanner', r'ryanair', r'easyjet',
    ],
    "Communication": [
        r'telegram\.org', r'signal\.org', r'whatsapp', r'protonmail',
        r'tutanota',
    ],
    "Dark Web / Anonymity": [
        r'\.onion', r'tor2web', r'darkweb', r'deepweb',
    ],
}

HIGH_RISK_CATEGORIES = {"P2P crypto exchange", "Dark Web / Anonymity", "VPN / Anonymization"}


def _categorize_url(url: str) -> list[str]:
    categories = []
    url_lower = url.lower()
    for category, patterns in CATEGORY_PATTERNS.items():
        if any(re.search(p, url_lower) for p in patterns):
            categories.append(category)
    return categories


def _extract_domain(url: str) -> str:
    match = re.search(r'https?://([^/?\s]+)', url)
    return match.group(1) if match else url[:50]


def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)
    findings = []
    artifacts_list = []
    alerts = []

    # ── 1. History ────────────────────────────────────────────────────────
    history_path = resolver.resolve_db("chrome_history")
    visited_categories = defaultdict(list)
    total_visits = 0

    if history_path:
        with SafeDBReader(history_path) as db:
            tables = db.tables()

            if "urls" in tables:
                url_rows = db.query(
                    "SELECT url, title, visit_count, last_visit_time "
                    "FROM urls ORDER BY last_visit_time DESC"
                )
                total_visits = len(url_rows)

                for row in url_rows:
                    url   = row.get("url") or ""
                    title = row.get("title") or ""
                    ts    = chrome_time_to_iso(row.get("last_visit_time"))
                    count = row.get("visit_count", 1)
                    domain = _extract_domain(url)
                    categories = _categorize_url(url)

                    for cat in categories:
                        visited_categories[cat].append({
                            "url": url[:120],
                            "title": title[:80],
                            "ts": ts,
                            "count": count,
                        })

                    if categories:
                        artifact_type = "crypto" if "crypto" in " ".join(categories).lower() else "web"
                        artifacts_list.append(artifact(
                            artifact_type,
                            f"[{', '.join(categories)}] {domain} – {title[:50] or url[:50]}",
                            "Chrome/History",
                            ts=ts,
                            extra={
                                "url": url[:200],
                                "domain": domain,
                                "categories": categories,
                                "visits": count,
                            },
                        ))
                    else:
                        artifacts_list.append(artifact(
                            "web",
                            f"{domain} – {title[:60] or url[:60]}",
                            "Chrome/History",
                            ts=ts,
                            extra={"url": url[:200], "domain": domain},
                        ))

            # Pretrage (keyword searches)
            if "keyword_search_terms" in tables:
                search_rows = db.query(
                    "SELECT term, url_id FROM keyword_search_terms LIMIT 50"
                )
                for row in search_rows:
                    term = row.get("term") or ""
                    if term:
                        artifacts_list.append(artifact(
                            "web",
                            f"🔍 Pretraga: \"{term}\"",
                            "Chrome/keyword_search_terms",
                            extra={"search_term": term},
                        ))

        findings.append(finding("Ukupno poseta", str(total_visits)))
        for cat, visits in sorted(visited_categories.items(), key=lambda x: -len(x[1])):
            findings.append(finding(f"Kategorija: {cat}", f"{len(visits)} poseta"))
            if cat in HIGH_RISK_CATEGORIES:
                urls_str = ", ".join(set(_extract_domain(v["url"]) for v in visits[:3]))
                alerts.append(f"VISOKI RIZIK: {cat} – {urls_str}")
    else:
        findings.append(finding("Chrome History", "Nije pronađena"))

    # ── 2. Login Data (sačuvane lozinke) ─────────────────────────────────
    login_path = resolver.resolve_db("chrome_login")
    if login_path:
        with SafeDBReader(login_path) as db:
            if "logins" in db.tables():
                login_rows = db.query(
                    "SELECT origin_url, username_value, date_created, times_used "
                    "FROM logins ORDER BY times_used DESC"
                )
                findings.append(finding("Sačuvani nalozi (Login Data)", str(len(login_rows))))

                for row in login_rows:
                    origin = row.get("origin_url") or ""
                    username = row.get("username_value") or ""
                    ts = chrome_time_to_iso(row.get("date_created"))
                    times_used = row.get("times_used", 0)
                    domain = _extract_domain(origin)
                    categories = _categorize_url(origin)

                    if username:
                        artifacts_list.append(artifact(
                            "account",
                            f"Login: {username} @ {domain} (korišćeno {times_used}x)",
                            "Chrome/Login Data",
                            ts=ts,
                            extra={
                                "username": username,
                                "domain": domain,
                                "categories": categories,
                                "times_used": times_used,
                            },
                        ))
                        if categories:
                            alerts.append(
                                f"Nalog na {', '.join(categories)} servisu: "
                                f"{username} @ {domain}"
                            )
    else:
        findings.append(finding("Chrome Login Data", "Nije pronađena"))

    # ── 3. Cookies (aktivne sesije) ───────────────────────────────────────
    cookies_path = resolver.resolve_db("chrome_cookies")
    if cookies_path:
        with SafeDBReader(cookies_path) as db:
            cookie_tables = db.tables()
            # Noviji Chrome ima "cookies" tabelu, stariji "cookies" ili "meta"
            for tbl in ["cookies", "Cookies"]:
                if tbl in cookie_tables:
                    cookie_rows = db.query(
                        f"SELECT host_key, name, expires_utc, last_access_utc "
                        f"FROM {tbl} ORDER BY last_access_utc DESC LIMIT 100"
                    )
                    findings.append(finding("Cookie sesije (top 100)", str(len(cookie_rows))))

                    # Grupiši po domenu
                    cookie_domains = defaultdict(int)
                    for row in cookie_rows:
                        host = row.get("host_key") or ""
                        cookie_domains[host] += 1

                    for host, count in sorted(cookie_domains.items(), key=lambda x: -x[1])[:10]:
                        categories = _categorize_url(host)
                        if categories:
                            artifacts_list.append(artifact(
                                "web",
                                f"Aktivna sesija: {host} ({count} cookie-ja) [{', '.join(categories)}]",
                                "Chrome/Cookies",
                                extra={"host": host, "cookie_count": count, "categories": categories},
                            ))
                            if any(c in HIGH_RISK_CATEGORIES for c in categories):
                                alerts.append(f"Aktivna sesija na {', '.join(categories)}: {host}")
                    break

    return module_result(
        status="completed",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
