"""
report_engine.py
────────────────
ForensicReportEngine — generator samostalnog (self-contained), print-ready
HTML izveštaja sa zaštitom integriteta (tamper-evident).

Ulaz: dict koji vraća main._collect_report_data():
    results, dump_path, created, device_str, android_str, now,
    all_alerts (lista tuple-ova), timeline, correlations, headline,
    total_artifacts

Izlaz: render() -> str — kompletan HTML dokument (inline CSS, bez
eksternih resursa, bez JavaScript-a) sa završnim blokom
"Integritet izveštaja" koji sadrži UUID izveštaja i SHA-256 otisak
tela dokumenta.

Samo standardna biblioteka (hashlib, html, uuid).
"""

import hashlib
import html
import uuid


# Labele tipova artefakata za narativnu rekonstrukciju (usklađeno sa main.py)
HEADLINE_TYPE_LABELS = {
    "call": "POZIV",
    "location": "LOKACIJA",
    "crypto": "KRIPTO TRANSAKCIJA/ADRESA",
    "comm": "KOMUNIKACIJA",
    "app": "APLIKACIJA",
    "media": "MEDIJA",
    "account": "NALOG/IDENTITET",
    "web": "WEB AKTIVNOST",
}

DISCLAIMER = (
    "Ovaj izveštaj sadrži faktografske nalaze (objektivni podaci). "
    "Pravna interpretacija i krivična kvalifikacija isključivo su "
    "u nadležnosti organa postupka."
)


def _esc(value) -> str:
    """HTML-escape bilo koje dinamičke vrednosti; None -> prazan string."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _split_ts(ts):
    """ISO ts -> (datum, vreme). Toleriše None i ne-ISO stringove."""
    if not ts:
        return ("", "")
    s = str(ts).replace("Z", "")
    date_part, _, time_part = s.partition("T")
    return (date_part, time_part)


class ForensicReportEngine:
    """Tamper-evident, print-ready HTML izveštaj za Android forenziku."""

    MAX_ALERTS_PER_MODULE = 15
    MAX_TIMELINE_ROWS = 500

    def __init__(self, data: dict):
        self.data = data or {}
        self.report_id = str(uuid.uuid4())

    # ── javni API ────────────────────────────────────────────────────────

    def render(self) -> str:
        body_sections = [
            self._header(),
            self._executive_summary(),
            self._reconstruction(),
            self._alerts(),
            self._module_results(),
            self._correlations(),
            self._detailed_timeline(),
            self._conclusion(),
        ]
        body = "\n".join(body_sections)

        # SHA-256 nad kompletnim telom PRE ubacivanja bloka o integritetu.
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        body += "\n" + self._integrity_block(digest)
        body += "\n" + self._footer()

        return self._document(body)

    # ── pomoćni pristup podacima ────────────────────────────────────────

    @property
    def _results(self) -> dict:
        return self.data.get("results") or {}

    @property
    def _all_alerts(self) -> list:
        return self.data.get("all_alerts") or []

    @property
    def _timeline(self) -> list:
        return self.data.get("timeline") or []

    def _get_correlations(self) -> list:
        return self.data.get("correlations") or []

    def _get_headline(self) -> list:
        return self.data.get("headline") or []

    # ── sekcije ──────────────────────────────────────────────────────────

    def _header(self) -> str:
        d = self.data
        # NAPOMENA: report_id (jedinstven po generisanju, slučajan) se NE
        # prikazuje ovde jer je deo tela koje se heš-ira. Da bi SHA-256 otisak
        # bio deterministički otisak SADRŽAJA (isti dokazi → isti otisak, čime
        # se dokazuje da analiza nije menjana), report_id se prikazuje isključivo
        # u bloku o integritetu koji se dodaje POSLE računanja heša.
        rows = [
            ("Uređaj", d.get("device_str") or "Nepoznat uređaj"),
            ("Android", d.get("android_str") or "N/A"),
            ("Dump putanja", d.get("dump_path") or "N/A"),
            ("Sesija otvorena", d.get("created") or "N/A"),
            ("Izveštaj generisan", d.get("now") or "N/A"),
        ]
        trs = "".join(
            f'<tr><th scope="row">{_esc(k)}</th><td>{_esc(v)}</td></tr>'
            for k, v in rows
        )
        return (
            '<header class="report-header">'
            "<h1>Forenzički izveštaj — Android mobilna forenzika</h1>"
            '<p class="subtitle">Android Forensic Dashboard v1.0 — logički '
            "filesystem dump, read-only pristup; originalni dump nije "
            "modifikovan.</p>"
            f'<table class="meta-table"><tbody>{trs}</tbody></table>'
            "</header>"
        )

    def _executive_summary(self) -> str:
        metrics = [
            (len(self._results), "Analizirano modula"),
            (self.data.get("total_artifacts", 0), "Ukupno artefakata"),
            (len(self._all_alerts), "Upozorenja"),
            (len(self._get_correlations()), "Korelacije između izvora"),
            (len(self._get_headline()), "Događaja u rekonstrukciji"),
        ]
        cards = "".join(
            f'<div class="metric"><div class="metric-value">{_esc(v)}</div>'
            f'<div class="metric-label">{_esc(label)}</div></div>'
            for v, label in metrics
        )
        return (
            '<section class="section">'
            "<h2>Izvršni rezime</h2>"
            f'<div class="metric-cards">{cards}</div>'
            "</section>"
        )

    def _reconstruction(self) -> str:
        headline = self._get_headline()
        parts = [
            '<section class="section major">',
            f"<h2>Rekonstrukcija događaja ({len(headline)})</h2>",
            '<p class="lead">Hronološki prikaz najznačajnijih događaja iz '
            "svih izvora — pozivi, lokacije, kripto transakcije, šifrovana "
            "komunikacija, sumnjive aplikacije i identitetski artefakti.</p>",
        ]
        if not headline:
            parts.append(
                '<p class="muted">Nema dovoljno podataka za rekonstrukciju '
                "događaja.</p>"
            )
        else:
            last_date = None
            open_group = False
            for e in headline:
                e = e or {}
                date_part, time_part = _split_ts(e.get("ts"))
                date_label = date_part or "Nepoznat datum"
                if date_label != last_date:
                    if open_group:
                        parts.append("</div>")
                    parts.append(
                        f'<h3 class="date-heading">{_esc(date_label)}</h3>'
                        '<div class="event-group">'
                    )
                    open_group = True
                    last_date = date_label
                etype = e.get("type") or "?"
                label = HEADLINE_TYPE_LABELS.get(etype, str(etype).upper())
                source = e.get("source") or ""
                src_html = (
                    f'<span class="event-source">— {_esc(source)}</span>'
                    if source else ""
                )
                parts.append(
                    '<div class="event">'
                    f'<span class="event-time">{_esc(time_part or "??:??:??")}</span>'
                    f'<span class="badge badge-type">{_esc(label)}</span>'
                    f'<span class="event-desc">{_esc(e.get("value", ""))}</span>'
                    f"{src_html}"
                    "</div>"
                )
            if open_group:
                parts.append("</div>")
        parts.append("</section>")
        return "".join(parts)

    def _alerts(self) -> str:
        all_alerts = self._all_alerts
        parts = [
            '<section class="section major">',
            f"<h2>Upozorenja ({len(all_alerts)})</h2>",
        ]
        if not all_alerts:
            parts.append('<p class="muted">Nema upozorenja.</p>')
        else:
            grouped: dict = {}
            for item in all_alerts:
                try:
                    module_name, alert_text = item[0], item[1]
                except (TypeError, IndexError):
                    module_name, alert_text = "?", item
                grouped.setdefault(str(module_name), []).append(alert_text)

            for module_name, alerts in grouped.items():
                parts.append(
                    '<div class="alert-group">'
                    f'<h3 class="alert-module">{_esc(module_name)} '
                    f'<span class="count">({len(alerts)})</span></h3>'
                )
                shown = alerts[: self.MAX_ALERTS_PER_MODULE]
                for a in shown:
                    parts.append(f'<div class="alert-item">&#9888; {_esc(a)}</div>')
                hidden = len(alerts) - len(shown)
                if hidden > 0:
                    parts.append(
                        f'<div class="alert-more">… i još {hidden} upozorenja</div>'
                    )
                parts.append("</div>")
        parts.append("</section>")
        return "".join(parts)

    def _module_results(self) -> str:
        results = self._results
        parts = [
            '<section class="section major">',
            "<h2>Rezultati po modulima</h2>",
        ]
        if not results:
            parts.append('<p class="muted">Nema rezultata modula.</p>')
        for module_name, data in results.items():
            data = data or {}
            status = data.get("status", "?")
            findings = data.get("findings") or []
            artifacts = data.get("artifacts") or []
            status_cls = "status-ok" if status == "ok" else "status-nf"
            status_label = "OK" if status == "ok" else "NIJE PRONAĐENO"
            parts.append(
                '<div class="module-block">'
                f'<h3 class="module-name">{_esc(module_name)} '
                f'<span class="badge {status_cls}">{_esc(status_label)}</span> '
                f'<span class="count">artefakata: {len(artifacts)}</span></h3>'
            )
            if findings:
                rows = "".join(
                    "<tr>"
                    f'<th scope="row">{_esc((f or {}).get("key"))}</th>'
                    f'<td>{_esc((f or {}).get("value"))}</td>'
                    "</tr>"
                    for f in findings
                )
                parts.append(
                    f'<table class="findings-table"><tbody>{rows}</tbody></table>'
                )
            else:
                parts.append('<p class="muted">Nema nalaza.</p>')
            parts.append("</div>")
        parts.append("</section>")
        return "".join(parts)

    def _correlations(self) -> str:
        correlations = self._get_correlations()
        parts = [
            '<section class="section major">',
            f"<h2>Korelacije ({len(correlations)})</h2>",
        ]
        if not correlations:
            parts.append(
                '<p class="muted">Nema pronađenih korelacija između izvora.</p>'
            )
        for c in correlations:
            c = c or {}
            confidence = str(c.get("confidence") or "")
            conf_cls = (
                "badge-conf-high" if confidence == "VISOKA" else "badge-conf-med"
            )
            sources = c.get("sources") or []
            sources_str = " + ".join(str(s) for s in sources)
            parts.append(
                '<div class="callout">'
                '<div class="callout-head">'
                f'<span class="corr-id">[{_esc(c.get("id"))}]</span> '
                f'<strong>{_esc(c.get("title"))}</strong> '
                f'<span class="badge {conf_cls}">{_esc(confidence or "N/A")}</span>'
                "</div>"
                f'<div class="corr-sources">Izvori: {_esc(sources_str)}</div>'
                f'<div class="corr-detail">{_esc(c.get("detail"))}</div>'
                "</div>"
            )
        parts.append("</section>")
        return "".join(parts)

    def _detailed_timeline(self) -> str:
        timeline = self._timeline
        total = len(timeline)
        shown = timeline[: self.MAX_TIMELINE_ROWS]
        parts = [
            '<section class="section major">',
            f"<h2>Detaljna vremenska linija ({total} događaja)</h2>",
        ]
        if total > self.MAX_TIMELINE_ROWS:
            parts.append(
                '<p class="truncation-note">Prikazano je prvih '
                f"{self.MAX_TIMELINE_ROWS} od ukupno {total} događaja "
                "(sortirano hronološki). Kompletna lista je dostupna preko "
                "API-ja (/api/session/&#123;id&#125;/timeline).</p>"
            )
        if not shown:
            parts.append(
                '<p class="muted">Nema događaja u vremenskoj liniji.</p>'
            )
        else:
            rows = []
            for e in shown:
                e = e or {}
                ts = e.get("ts")
                ts_str = (
                    str(ts).replace("T", " ").replace("Z", "") if ts else "N/A"
                )
                severity = e.get("severity")
                if severity in ("high", "medium", "low"):
                    dot = f'<span class="dot dot-{severity}" title="{_esc(severity)}"></span>'
                else:
                    dot = ""
                rows.append(
                    "<tr>"
                    f'<td class="cell-sev">{dot}</td>'
                    f'<td class="cell-ts">{_esc(ts_str)}</td>'
                    f'<td class="cell-type">{_esc(str(e.get("type") or "?").upper())}</td>'
                    f'<td class="cell-val">{_esc(e.get("value"))}</td>'
                    f'<td class="cell-src">{_esc(e.get("source"))}</td>'
                    f'<td class="cell-mod">{_esc(e.get("module"))}</td>'
                    "</tr>"
                )
            parts.append(
                '<table class="timeline-table"><thead><tr>'
                "<th></th><th>Vreme (UTC)</th><th>Tip</th><th>Opis</th>"
                "<th>Izvor</th><th>Modul</th>"
                "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
            )
        parts.append("</section>")
        return "".join(parts)

    def _conclusion(self) -> str:
        return (
            '<section class="section major">'
            "<h2>Forenzički zaključak</h2>"
            f'<p class="conclusion">{_esc(DISCLAIMER)}</p>'
            "</section>"
        )

    def _integrity_block(self, digest: str) -> str:
        rows = [
            ("ID izveštaja", self.report_id),
            ("Vreme generisanja", self.data.get("now") or "N/A"),
            ("SHA-256 otisak", digest),
            ("Broj artefakata", self.data.get("total_artifacts", 0)),
            ("Broj upozorenja", len(self._all_alerts)),
            ("Broj korelacija", len(self._get_correlations())),
            ("Broj događaja u vremenskoj liniji", len(self._timeline)),
        ]
        trs = "".join(
            f'<tr><th scope="row">{_esc(k)}</th>'
            f'<td class="mono">{_esc(v)}</td></tr>'
            for k, v in rows
        )
        return (
            '<section class="section major integrity">'
            "<h2>Integritet izveštaja</h2>"
            f'<table class="meta-table"><tbody>{trs}</tbody></table>'
            '<p class="integrity-note">SHA-256 otisak je izračunat nad '
            "kompletnim telom izveštaja pre umetanja ovog bloka; svaka "
            "naknadna izmena sadržaja dokumenta poništava važenje navedenog "
            "otiska i ukazuje na narušen integritet izveštaja.</p>"
            "</section>"
        )

    def _footer(self) -> str:
        now = self.data.get("now") or ""
        return (
            '<footer class="report-footer">'
            f'<p class="disclaimer">{_esc(DISCLAIMER)}</p>'
            f'<p class="footer-meta">Android Forensic Dashboard v1.0 — '
            f"{_esc(now)} — ID izveštaja: {_esc(self.report_id)}</p>"
            "</footer>"
        )

    # ── omotač dokumenta ─────────────────────────────────────────────────

    def _document(self, body: str) -> str:
        return (
            "<!DOCTYPE html>\n"
            '<html lang="sr">\n'
            "<head>\n"
            '<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            "<title>Forenzički izveštaj — Android mobilna forenzika</title>\n"
            f"<style>{self._css()}</style>\n"
            "</head>\n"
            "<body>\n"
            f"{body}\n"
            "</body>\n"
            "</html>\n"
        )

    @staticmethod
    def _css() -> str:
        return """
:root {
  --ink: #1e293b;
  --ink-strong: #0f172a;
  --muted: #64748b;
  --line: #e2e8f0;
  --panel: #f8fafc;
  --red: #b91c1c;
  --red-bg: #fef2f2;
  --amber: #b45309;
  --amber-bg: #fffbeb;
  --slate-badge: #475569;
}
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               "Helvetica Neue", Arial, "Noto Sans", sans-serif;
  color: var(--ink);
  background: #ffffff;
  margin: 0 auto;
  max-width: 980px;
  padding: 48px 56px 64px;
  line-height: 1.55;
  font-size: 14px;
}
h1 {
  font-size: 25px;
  color: var(--ink-strong);
  margin: 0 0 6px;
  letter-spacing: -0.02em;
  line-height: 1.25;
}
.subtitle { color: var(--muted); font-size: 12.5px; margin: 0 0 22px; }
h2 {
  font-size: 16px;
  color: var(--ink-strong);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  border-bottom: 2px solid var(--ink-strong);
  padding-bottom: 7px;
  margin: 48px 0 18px;
}
h3 { font-size: 13px; color: #334155; margin: 22px 0 8px; }
p { margin: 0 0 10px; }
.lead { color: var(--muted); font-size: 13px; }
.muted { color: var(--muted); font-style: italic; }
.count { color: var(--muted); font-weight: 400; font-size: 12px; }
.mono {
  font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono",
               Menlo, monospace;
  font-size: 12px;
  word-break: break-all;
}

table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; vertical-align: top; }

.meta-table { margin: 0 0 8px; page-break-inside: avoid; }
.meta-table th {
  width: 220px;
  color: var(--muted);
  font-weight: 500;
  padding: 6px 14px 6px 0;
  border-bottom: 1px solid var(--line);
  white-space: nowrap;
}
.meta-table td {
  padding: 6px 0;
  border-bottom: 1px solid var(--line);
  word-break: break-word;
}

.metric-cards {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  page-break-inside: avoid;
}
.metric {
  flex: 1 1 150px;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 14px 16px;
  text-align: center;
}
.metric-value {
  font-size: 26px;
  font-weight: 700;
  color: var(--ink-strong);
  line-height: 1.1;
}
.metric-label {
  font-size: 11px;
  color: var(--muted);
  margin-top: 6px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.date-heading {
  color: var(--ink-strong);
  border-bottom: 1px solid var(--line);
  padding-bottom: 4px;
}
.event-group { margin: 0 0 6px; }
.event {
  padding: 5px 0 5px 4px;
  border-bottom: 1px dotted var(--line);
  page-break-inside: avoid;
}
.event-time { font-weight: 700; color: var(--ink-strong); margin-right: 8px;
  font-variant-numeric: tabular-nums; }
.event-desc { margin-left: 8px; }
.event-source { color: #94a3b8; font-size: 11.5px; margin-left: 8px; }

.badge {
  display: inline-block;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.05em;
  padding: 2px 8px;
  border-radius: 3px;
  text-transform: uppercase;
  vertical-align: middle;
}
.badge-type { background: #eef2f7; color: var(--slate-badge);
  border: 1px solid var(--line); }
.badge-conf-high { background: var(--red-bg); color: var(--red);
  border: 1px solid #fecaca; }
.badge-conf-med { background: var(--amber-bg); color: var(--amber);
  border: 1px solid #fde68a; }
.status-ok { background: #f1f5f9; color: var(--slate-badge);
  border: 1px solid var(--line); }
.status-nf { background: var(--amber-bg); color: var(--amber);
  border: 1px solid #fde68a; }

.alert-group { margin: 0 0 18px; page-break-inside: avoid; }
.alert-module { margin-bottom: 6px; }
.alert-item {
  color: var(--red);
  background: var(--red-bg);
  border-left: 3px solid var(--red);
  padding: 5px 10px;
  margin: 4px 0;
  font-size: 13px;
  page-break-inside: avoid;
}
.alert-more { color: var(--muted); font-style: italic; padding: 4px 10px; }

.module-block { margin: 0 0 22px; page-break-inside: avoid; }
.module-name { margin-bottom: 8px; }
.findings-table th {
  width: 260px;
  color: var(--muted);
  font-weight: 500;
  padding: 5px 14px 5px 0;
  border-bottom: 1px solid var(--line);
}
.findings-table td {
  padding: 5px 0;
  border-bottom: 1px solid var(--line);
  word-break: break-word;
}

.callout {
  background: var(--panel);
  border: 1px solid var(--line);
  border-left: 4px solid var(--slate-badge);
  border-radius: 4px;
  padding: 12px 16px;
  margin: 0 0 14px;
  page-break-inside: avoid;
}
.callout-head { margin-bottom: 6px; }
.corr-id { color: var(--muted); font-size: 12px; }
.corr-sources { color: var(--muted); font-size: 12px; margin-bottom: 4px; }
.corr-detail { font-size: 13px; }

.truncation-note {
  background: var(--amber-bg);
  border: 1px solid #fde68a;
  color: var(--amber);
  border-radius: 4px;
  padding: 8px 12px;
  font-size: 12.5px;
}
.timeline-table { font-size: 12px; }
.timeline-table thead th {
  border-bottom: 2px solid var(--ink-strong);
  padding: 6px 8px 6px 0;
  color: var(--ink-strong);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.timeline-table tbody td {
  border-bottom: 1px solid var(--line);
  padding: 4px 8px 4px 0;
  word-break: break-word;
}
.timeline-table tbody tr { page-break-inside: avoid; }
.cell-sev { width: 16px; }
.cell-ts { white-space: nowrap; font-variant-numeric: tabular-nums; }
.cell-type { white-space: nowrap; color: var(--slate-badge); font-weight: 600; }
.cell-src, .cell-mod { color: var(--muted); }
.dot {
  display: inline-block;
  width: 8px; height: 8px;
  border-radius: 50%;
  vertical-align: middle;
}
.dot-high { background: var(--red); }
.dot-medium { background: #d97706; }
.dot-low { background: #94a3b8; }

.conclusion { font-size: 13.5px; }
.integrity .integrity-note { color: var(--muted); font-size: 12.5px; }

.report-footer {
  margin-top: 56px;
  border-top: 1px solid var(--line);
  padding-top: 14px;
  color: var(--muted);
  font-size: 11.5px;
}
.disclaimer { font-style: italic; }
.footer-meta { margin-top: 4px; }

@page { margin: 2cm; }
@media print {
  body { max-width: none; padding: 0; font-size: 11.5px; }
  h2 { margin-top: 0; padding-top: 12px; }
  section.major { page-break-before: always; }
  .metric { border: 1px solid #cbd5e1; }
  a { color: inherit; text-decoration: none; }
}
"""
