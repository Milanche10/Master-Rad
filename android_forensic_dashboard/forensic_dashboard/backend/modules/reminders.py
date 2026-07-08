"""
modules/reminders.py
────────────────────
Ekstrakcija PODSETNIKA / ZADATAKA / ALARMA sa Android uređaja:

  - Samsung Reminder      (com.samsung.android.app.reminder → reminder.db)
      tabele: reminder (title, item_status, time_created), alarm_event (alert_time,
      remind_time), dates (start_time/end_time), contents (text stavki/checklist)
  - Samsung / AOSP Calendar podsetnici (calendar.db)
      Events (title, dtstart, description) + Reminders / CalendarAlerts (alarmTime)
  - Google Tasks          (com.google.android.apps.tasks → databases)
  - Clock / alarmi        (com.sec.android.app.clockpackage / com.google.android.deskclock
      → alarm.db / alarms) — zakazani alarmi

Za svaki izvor: reminder/task/event zapis → artifact type_="reminder",
value=naslov, ts=vreme dospeća/alarma (ms ili sec — detekcija po veličini),
extra={app, title, due, status/complete, description, package}.

Detektuje i FLAG-uje šifrovane/nečitljive baze umesto lažnog čitanja.
Defanzivno: sve tabele/kolone se proveravaju pre upita; nedostajuće
ne ruše modul.
"""

from pathlib import Path
from collections import defaultdict
from typing import Optional

from utils.dump_resolver import DumpResolver, DATA_ROOTS
from utils.db_reader import SafeDBReader
from utils.helpers import (
    artifact, finding, module_result, not_found_result,
    ms_to_iso, sec_to_iso,
)

# Maksimalan broj zapisa po skeniranju (zaštita od ogromnih baza)
MAX_ROWS = 5000

# Paketi koji nose podsetnike/zadatke/alarme
PKG_SAMSUNG_REMINDER = "com.samsung.android.app.reminder"
PKG_GOOGLE_TASKS = "com.google.android.apps.tasks"
PKG_SAMSUNG_CLOCK = "com.sec.android.app.clockpackage"
PKG_GOOGLE_CLOCK = "com.google.android.deskclock"

# Samsung Reminder item_status → čitljiv status
REMINDER_STATUS_MAP = {
    0: "aktivan",
    1: "završen",
    2: "obrisan",
}

# SQLite header — za detekciju da li je baza plaintext ili šifrovana/oštećena
SQLITE_MAGIC = b"SQLite format 3\x00"


# ─── POMOĆNE ──────────────────────────────────────────────────────────────

def _epoch_to_iso(value) -> Optional[str]:
    """
    Konvertuj epoch u ISO, autodetekcija ms vs sec po redu veličine.
    ≥ 1e12  → milisekunde (npr. 1618929900000)
    < 1e12  → sekunde     (npr. 1618929900)
    """
    if value is None:
        return None
    try:
        v = int(value)
    except (ValueError, TypeError):
        return None
    if v <= 0:
        return None
    if v >= 1_000_000_000_000:   # ~2001+ u ms
        return ms_to_iso(v)
    return sec_to_iso(v)


def _first_col(cols, candidates):
    """Vrati prvu kolonu iz `candidates` koja postoji u `cols`, ili None."""
    for c in candidates:
        if c in cols:
            return c
    return None


def _clip(text, n=200):
    """Skrati opis na n karaktera (za extra.description)."""
    if text is None:
        return None
    s = str(text)
    return s if len(s) <= n else s[:n]


def _is_plaintext_sqlite(path: Path) -> bool:
    """Da li fajl počinje plaintext SQLite potpisom (nešifrovan)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(16) == SQLITE_MAGIC
    except Exception:
        return False


def _all_pkg_roots(resolver: DumpResolver, package: str):
    """
    Svi data root-ovi za paket (data/data, data/user/0, data/user_de/0).
    pkg_root() vraća samo PRVI; neke baze (npr. Samsung alarm.db) žive samo
    u data/user_de/0 pa moramo obići sve.
    """
    roots = []
    for data_root in DATA_ROOTS:
        candidate = resolver.root / data_root / package
        if candidate.exists() and candidate.is_dir():
            roots.append(candidate)
    return roots


def _dbs_for_package_all_roots(resolver: DumpResolver, package: str):
    """Sve *.db baze paketa iz SVIH data root-ova (dedup po imenu fajla)."""
    seen = {}
    for root in _all_pkg_roots(resolver, package):
        db_dir = root / "databases"
        if not db_dir.exists():
            continue
        for db in db_dir.glob("*.db"):
            # ključ = ime fajla; preferiraj najveću kopiju
            try:
                size = db.stat().st_size
            except Exception:
                size = 0
            prev = seen.get(db.name)
            if prev is None or size > prev[0]:
                seen[db.name] = (size, db)
    return [v[1] for v in seen.values()]


# ─── IZVORI ───────────────────────────────────────────────────────────────

def _analyze_samsung_reminder(resolver, findings, artifacts_list, alerts) -> int:
    """Samsung Reminder (reminder.db). Vraća broj ekstraktovanih podsetnika."""
    dbs = _dbs_for_package_all_roots(resolver, PKG_SAMSUNG_REMINDER)
    target = None
    for db in dbs:
        if db.name == "reminder.db":
            target = db
            break
    if target is None and dbs:
        target = dbs[0]
    if target is None:
        return 0

    if not _is_plaintext_sqlite(target):
        try:
            size = target.stat().st_size
        except Exception:
            size = 0
        alerts.append(
            f"Samsung Reminder baza nije čitljiva (šifrovana/oštećena): "
            f"{target.name} ({size}B) — {target}"
        )
        findings.append(finding("Samsung Reminder", "baza nečitljiva (flag)"))
        return 0

    count = 0
    with SafeDBReader(target) as db:
        tables = db.tables()
        if "reminder" not in tables:
            return 0

        rcols = db.columns("reminder")
        id_col = _first_col(rcols, ["uuid", "_id"])
        title_col = _first_col(rcols, ["title"])
        status_col = _first_col(rcols, ["item_status"])
        created_col = _first_col(rcols, ["time_created", "last_modified_time"])

        # Mapa alarm vremena po reminder_uuid (ako tabela postoji)
        alarm_by_uuid = {}
        if "alarm_event" in tables:
            acols = db.columns("alarm_event")
            a_uuid = _first_col(acols, ["reminder_uuid"])
            a_time = _first_col(acols, ["alert_time", "remind_time", "notification_time"])
            if a_uuid and a_time:
                for ar in db.query(
                    f'SELECT "{a_uuid}" AS u, "{a_time}" AS t FROM alarm_event'
                ):
                    if ar.get("u") is not None and ar.get("t"):
                        alarm_by_uuid.setdefault(ar["u"], ar["t"])

        # Mapa datuma po reminder_uuid (start_time)
        date_by_uuid = {}
        if "dates" in tables:
            dcols = db.columns("dates")
            d_uuid = _first_col(dcols, ["reminder_uuid"])
            d_time = _first_col(dcols, ["start_time", "end_time"])
            if d_uuid and d_time:
                for dr in db.query(
                    f'SELECT "{d_uuid}" AS u, "{d_time}" AS t FROM dates'
                ):
                    if dr.get("u") is not None and dr.get("t"):
                        date_by_uuid.setdefault(dr["u"], dr["t"])

        # Mapa tekstualnog sadržaja/checklist po reminder_uuid
        content_by_uuid = defaultdict(list)
        if "contents" in tables:
            ccols = db.columns("contents")
            c_uuid = _first_col(ccols, ["reminder_uuid"])
            c_text = _first_col(ccols, ["text"])
            if c_uuid and c_text:
                for cr in db.query(
                    f'SELECT "{c_uuid}" AS u, "{c_text}" AS t FROM contents'
                ):
                    if cr.get("u") is not None and cr.get("t"):
                        content_by_uuid[cr["u"]].append(str(cr["t"]))

        sel = []
        if id_col:
            sel.append(f'"{id_col}" AS rid')
        if title_col:
            sel.append(f'"{title_col}" AS title')
        if status_col:
            sel.append(f'"{status_col}" AS status')
        if created_col:
            sel.append(f'"{created_col}" AS created')
        if not sel:
            return 0

        rows = db.query(f'SELECT {", ".join(sel)} FROM reminder LIMIT {MAX_ROWS}')
        status_counts = defaultdict(int)
        for row in rows:
            rid = row.get("rid")
            title = (row.get("title") or "").strip() or "(bez naslova)"
            status_raw = row.get("status")
            created = row.get("created")

            due = alarm_by_uuid.get(rid) or date_by_uuid.get(rid)
            ts = _epoch_to_iso(due) or _epoch_to_iso(created)

            try:
                status_str = REMINDER_STATUS_MAP.get(int(status_raw), f"status_{status_raw}")
            except (ValueError, TypeError):
                status_str = str(status_raw) if status_raw is not None else "n/a"
            status_counts[status_str] += 1

            desc = "; ".join(content_by_uuid.get(rid, []))
            artifacts_list.append(artifact(
                "reminder",
                f"Samsung Reminder: {title}",
                "reminder.db",
                ts=ts,
                extra={
                    "app": "Samsung Reminder",
                    "package": PKG_SAMSUNG_REMINDER,
                    "title": title,
                    "due": _epoch_to_iso(due),
                    "status": status_str,
                    "description": _clip(desc) if desc else None,
                },
            ))
            count += 1

        if count:
            findings.append(finding("Samsung Reminder — podsetnici", str(count)))
            for st, c in sorted(status_counts.items(), key=lambda x: -x[1]):
                findings.append(finding(f"  {st}", str(c)))
        else:
            findings.append(finding("Samsung Reminder", "baza prisutna, 0 podsetnika"))

    return count


def _analyze_calendar(resolver, findings, artifacts_list, alerts) -> int:
    """Kalendarski događaji/podsetnici (calendar.db). Vraća broj događaja."""
    # any_of=False (obe tabele) — 'Events' sam po sebi kolidira sa drugim bazama
    # (npr. Spotify event-sender.db ima 'Events'); pravi kalendar ima i 'Calendars'.
    db_path = resolver.find_db_by_schema({"Events", "Calendars"}, any_of=False)
    if not db_path:
        return 0

    if not _is_plaintext_sqlite(db_path):
        alerts.append(f"Kalendar baza nije čitljiva (šifrovana/oštećena): {db_path}")
        return 0

    count = 0
    with SafeDBReader(db_path) as db:
        tables = db.tables()
        if "Events" not in tables:
            return 0

        ecols = db.columns("Events")
        title_col = _first_col(ecols, ["title"])
        start_col = _first_col(ecols, ["dtstart"])
        desc_col = _first_col(ecols, ["description"])
        loc_col = _first_col(ecols, ["eventLocation"])
        del_col = _first_col(ecols, ["deleted"])
        id_col = _first_col(ecols, ["_id"])
        has_alarm_col = _first_col(ecols, ["hasAlarm"])

        # Mapa alarm vremena po event_id iz CalendarAlerts / Reminders(minutes)
        alarm_by_event = {}
        if "CalendarAlerts" in tables:
            acols = db.columns("CalendarAlerts")
            a_ev = _first_col(acols, ["event_id"])
            a_time = _first_col(acols, ["alarmTime", "begin"])
            if a_ev and a_time:
                for ar in db.query(
                    f'SELECT "{a_ev}" AS ev, "{a_time}" AS t FROM CalendarAlerts'
                ):
                    if ar.get("ev") is not None and ar.get("t"):
                        alarm_by_event.setdefault(ar["ev"], ar["t"])

        reminder_minutes_by_event = {}
        if "Reminders" in tables:
            rcols = db.columns("Reminders")
            r_ev = _first_col(rcols, ["event_id"])
            r_min = _first_col(rcols, ["minutes"])
            if r_ev and r_min:
                for rr in db.query(
                    f'SELECT "{r_ev}" AS ev, "{r_min}" AS m FROM Reminders'
                ):
                    if rr.get("ev") is not None and rr.get("m") is not None:
                        reminder_minutes_by_event.setdefault(rr["ev"], rr["m"])

        sel = []
        if id_col:
            sel.append(f'"{id_col}" AS eid')
        if title_col:
            sel.append(f'"{title_col}" AS title')
        if start_col:
            sel.append(f'"{start_col}" AS dtstart')
        if desc_col:
            sel.append(f'"{desc_col}" AS descr')
        if loc_col:
            sel.append(f'"{loc_col}" AS loc')
        if del_col:
            sel.append(f'"{del_col}" AS deleted')
        if not sel:
            return 0

        rows = db.query(f'SELECT {", ".join(sel)} FROM Events LIMIT {MAX_ROWS}')
        deleted_count = 0
        with_reminder = 0
        for row in rows:
            eid = row.get("eid")
            title = (row.get("title") or "").strip() or "(bez naslova)"
            dtstart = row.get("dtstart")
            descr = row.get("descr")
            loc = row.get("loc")
            is_deleted = bool(row.get("deleted"))

            ts = _epoch_to_iso(dtstart)
            alarm = alarm_by_event.get(eid)
            due = alarm or dtstart
            has_rem = eid in alarm_by_event or eid in reminder_minutes_by_event
            if has_rem:
                with_reminder += 1
            if is_deleted:
                deleted_count += 1

            status = "obrisan" if is_deleted else ("sa podsetnikom" if has_rem else "događaj")

            artifacts_list.append(artifact(
                "reminder",
                f"Kalendar događaj: {title}" + (" [OBRISAN]" if is_deleted else ""),
                "calendar.db",
                ts=ts,
                extra={
                    "app": "Calendar",
                    "package": "com.android.providers.calendar",
                    "title": title,
                    "due": _epoch_to_iso(due),
                    "status": status,
                    "location": loc or None,
                    "reminder_minutes": reminder_minutes_by_event.get(eid),
                    "description": _clip(descr) if descr else None,
                },
            ))
            count += 1

        if count:
            findings.append(finding("Kalendar — događaji", str(count)))
            if with_reminder:
                findings.append(finding("  sa podsetnikom/alarmom", str(with_reminder)))
            if deleted_count:
                findings.append(finding("  obrisani događaji", str(deleted_count)))
                alerts.append(
                    f"Kalendar: {deleted_count} obrisan(ih) događaj(a) i dalje prisutn(o) u bazi"
                )

    return count


def _analyze_calendar_tasks(resolver, findings, artifacts_list, alerts) -> int:
    """Zadaci u calendar.db (Samsung Tasks tabela). Vraća broj zadataka."""
    db_path = resolver.find_db_by_schema({"Events", "Calendars"}, any_of=False)
    if not db_path or not _is_plaintext_sqlite(db_path):
        return 0

    count = 0
    with SafeDBReader(db_path) as db:
        if "Tasks" not in db.tables():
            return 0
        tcols = db.columns("Tasks")
        subj_col = _first_col(tcols, ["subject", "displayName"])
        due_col = _first_col(tcols, ["due_date", "utc_due_date"])
        start_col = _first_col(tcols, ["start_date"])
        complete_col = _first_col(tcols, ["complete"])
        completed_at_col = _first_col(tcols, ["date_completed"])
        body_col = _first_col(tcols, ["body"])
        del_col = _first_col(tcols, ["deleted"])
        if not subj_col:
            return 0

        sel = [f'"{subj_col}" AS subj']
        for c, alias in [
            (due_col, "due"), (start_col, "start"), (complete_col, "complete"),
            (completed_at_col, "completed_at"), (body_col, "body"), (del_col, "deleted"),
        ]:
            if c:
                sel.append(f'"{c}" AS {alias}')

        rows = db.query(f'SELECT {", ".join(sel)} FROM Tasks LIMIT {MAX_ROWS}')
        done = 0
        for row in rows:
            subj = (row.get("subj") or "").strip() or "(bez naslova)"
            due = row.get("due") or row.get("start")
            is_complete = bool(row.get("complete"))
            if is_complete:
                done += 1
            status = "završen" if is_complete else "aktivan"
            if row.get("deleted"):
                status = "obrisan"

            ts = _epoch_to_iso(due) or _epoch_to_iso(row.get("completed_at"))
            artifacts_list.append(artifact(
                "reminder",
                f"Zadatak (Calendar Tasks): {subj}",
                "calendar.db",
                ts=ts,
                extra={
                    "app": "Calendar Tasks",
                    "package": "com.android.providers.calendar",
                    "title": subj,
                    "due": _epoch_to_iso(due),
                    "complete": is_complete,
                    "status": status,
                    "description": _clip(row.get("body")) if row.get("body") else None,
                },
            ))
            count += 1

        if count:
            findings.append(finding("Calendar Tasks — zadaci", str(count)))
            findings.append(finding("  završeni", str(done)))

    return count


def _analyze_google_tasks(resolver, findings, artifacts_list, alerts) -> int:
    """Google Tasks (com.google.android.apps.tasks). Vraća broj zadataka."""
    dbs = _dbs_for_package_all_roots(resolver, PKG_GOOGLE_TASKS)
    if not dbs:
        return 0

    count = 0
    for target in dbs:
        if not _is_plaintext_sqlite(target):
            try:
                size = target.stat().st_size
            except Exception:
                size = 0
            alerts.append(
                f"Google Tasks baza nije čitljiva (šifrovana/oštećena): "
                f"{target.name} ({size}B)"
            )
            continue
        with SafeDBReader(target) as db:
            tables = db.tables()
            # Traži tabelu koja liči na tasks (ima title/text i completed/due kolone)
            for t in tables:
                if t in ("android_metadata", "sqlite_sequence"):
                    continue
                cols = db.columns(t)
                title_col = _first_col(cols, ["title", "text", "name", "task_title"])
                if not title_col:
                    continue
                due_col = _first_col(cols, ["due_date", "due", "due_time", "due_timestamp"])
                complete_col = _first_col(cols, ["completed", "is_completed", "complete", "done"])
                comp_time_col = _first_col(cols, ["completed_time", "completion_time", "date_completed"])
                notes_col = _first_col(cols, ["notes", "description", "body"])
                # zahtevamo bar naznaku da je ovo tabela zadataka
                if not (due_col or complete_col or comp_time_col):
                    continue

                sel = [f'"{title_col}" AS title']
                for c, alias in [
                    (due_col, "due"), (complete_col, "complete"),
                    (comp_time_col, "comp_time"), (notes_col, "notes"),
                ]:
                    if c:
                        sel.append(f'"{c}" AS {alias}')
                rows = db.query(f'SELECT {", ".join(sel)} FROM "{t}" LIMIT {MAX_ROWS}')
                if not rows:
                    continue
                for row in rows:
                    title = (row.get("title") or "").strip() or "(bez naslova)"
                    due = row.get("due")
                    is_complete = bool(row.get("complete"))
                    ts = _epoch_to_iso(due) or _epoch_to_iso(row.get("comp_time"))
                    artifacts_list.append(artifact(
                        "reminder",
                        f"Google Task: {title}",
                        target.name,
                        ts=ts,
                        extra={
                            "app": "Google Tasks",
                            "package": PKG_GOOGLE_TASKS,
                            "title": title,
                            "due": _epoch_to_iso(due),
                            "complete": is_complete,
                            "status": "završen" if is_complete else "aktivan",
                            "description": _clip(row.get("notes")) if row.get("notes") else None,
                        },
                    ))
                    count += 1

    if count:
        findings.append(finding("Google Tasks — zadaci", str(count)))
    return count


def _analyze_alarms(resolver, findings, artifacts_list, alerts) -> int:
    """Zakazani alarmi (Samsung clock alarm.db / Google deskclock). Vraća broj."""
    total = 0
    for pkg, app_name in [
        (PKG_SAMSUNG_CLOCK, "Samsung Clock"),
        (PKG_GOOGLE_CLOCK, "Google Clock"),
    ]:
        dbs = _dbs_for_package_all_roots(resolver, pkg)
        for target in dbs:
            # alarm baze: ime sadrži 'alarm', ili tabela 'alarm'/'alarms'
            with_alarm_name = "alarm" in target.name.lower()
            if not _is_plaintext_sqlite(target):
                if with_alarm_name:
                    try:
                        size = target.stat().st_size
                    except Exception:
                        size = 0
                    alerts.append(
                        f"{app_name} alarm baza nije čitljiva (šifrovana/oštećena): "
                        f"{target.name} ({size}B)"
                    )
                continue
            with SafeDBReader(target) as db:
                tables = db.tables()
                alarm_tbl = _first_col(tables, ["alarm", "alarms"])
                if not alarm_tbl:
                    continue
                cols = db.columns(alarm_tbl)
                # Samsung: alerttime (ms epoch), name, active, repeattype, createtime
                # AOSP deskclock: hour, minutes, enabled, label
                time_col = _first_col(cols, ["alerttime", "alarmtime", "alert_time"])
                name_col = _first_col(cols, ["name", "label", "message"])
                active_col = _first_col(cols, ["active", "enabled"])
                hour_col = _first_col(cols, ["hour", "hours"])
                min_col = _first_col(cols, ["minute", "minutes"])
                created_col = _first_col(cols, ["createtime", "created"])
                repeat_col = _first_col(cols, ["repeattype", "daysofweek", "days_of_week"])

                sel = []
                for c, alias in [
                    (time_col, "alerttime"), (name_col, "name"), (active_col, "active"),
                    (hour_col, "hour"), (min_col, "minute"), (created_col, "created"),
                    (repeat_col, "repeat"),
                ]:
                    if c:
                        sel.append(f'"{c}" AS {alias}')
                if not sel:
                    continue

                rows = db.query(
                    f'SELECT {", ".join(sel)} FROM "{alarm_tbl}" LIMIT {MAX_ROWS}'
                )
                cnt = 0
                active_cnt = 0
                for row in rows:
                    name = (row.get("name") or "").strip()
                    # AOSP alarmi nemaju epoch već hour:minute
                    hh = row.get("hour")
                    mm = row.get("minute")
                    if not name and hh is not None and mm is not None:
                        try:
                            name = f"Alarm {int(hh):02d}:{int(mm):02d}"
                        except (ValueError, TypeError):
                            name = "Alarm"
                    if not name:
                        name = "Alarm"

                    is_active = row.get("active")
                    active_str = ""
                    if is_active is not None:
                        try:
                            active_bool = bool(int(is_active))
                        except (ValueError, TypeError):
                            active_bool = bool(is_active)
                        active_str = "aktivan" if active_bool else "neaktivan"
                        if active_bool:
                            active_cnt += 1

                    # ts: alerttime (sledeće okidanje) ako je epoch, inače createtime
                    ts = _epoch_to_iso(row.get("alerttime")) or _epoch_to_iso(row.get("created"))

                    artifacts_list.append(artifact(
                        "reminder",
                        f"Alarm ({app_name}): {name}"
                        + (f" [{active_str}]" if active_str else ""),
                        target.name,
                        ts=ts,
                        extra={
                            "app": app_name,
                            "package": pkg,
                            "title": name,
                            "due": _epoch_to_iso(row.get("alerttime")),
                            "status": active_str or None,
                            "repeat": row.get("repeat"),
                            "description": None,
                        },
                    ))
                    cnt += 1
                if cnt:
                    total += cnt
                    findings.append(finding(f"{app_name} — alarmi", str(cnt)))
                    if active_col:
                        findings.append(finding(f"  aktivni", str(active_cnt)))
    return total


# ─── GLAVNI ULAZ ──────────────────────────────────────────────────────────

def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)

    findings = []
    artifacts_list = []
    alerts = []

    total = 0
    try:
        total += _analyze_samsung_reminder(resolver, findings, artifacts_list, alerts)
    except Exception as e:
        alerts.append(f"Greška pri čitanju Samsung Reminder baze: {e}")
    try:
        total += _analyze_calendar(resolver, findings, artifacts_list, alerts)
    except Exception as e:
        alerts.append(f"Greška pri čitanju kalendara: {e}")
    try:
        total += _analyze_calendar_tasks(resolver, findings, artifacts_list, alerts)
    except Exception as e:
        alerts.append(f"Greška pri čitanju Calendar Tasks: {e}")
    try:
        total += _analyze_google_tasks(resolver, findings, artifacts_list, alerts)
    except Exception as e:
        alerts.append(f"Greška pri čitanju Google Tasks: {e}")
    try:
        total += _analyze_alarms(resolver, findings, artifacts_list, alerts)
    except Exception as e:
        alerts.append(f"Greška pri čitanju alarma: {e}")

    if total > 0 and total >= MAX_ROWS:
        alerts.append(
            f"Dostignut limit skeniranja ({MAX_ROWS} zapisa po izvoru) — "
            f"moguće je da postoji još podsetnika/zadataka"
        )

    if not artifacts_list and not any(
        a for a in alerts if "nije čitljiva" in a
    ):
        # Nijedan izvor nije pronađen
        return not_found_result(
            "Reminders",
            "podsetnici/zadaci/alarmi (Samsung Reminder / Calendar / Google Tasks / Clock)"
        )

    findings.insert(0, finding("Ukupno podsetnika/zadataka/alarma", str(total)))

    return module_result(
        status="completed",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
