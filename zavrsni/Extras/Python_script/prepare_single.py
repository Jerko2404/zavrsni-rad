from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

# Timestamp na samom početku linije
FRONT_TIMESTAMP_RE = re.compile(
    r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)"
)

ISO_TS_IN_BRACKETS_RE = re.compile(
    r"\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?]"
)

APACHE_TS_IN_BRACKETS_RE = re.compile(
    r"\[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}]"
)

# Timestamp
INLINE_ISO_TS_RE = re.compile(
    r"(?<!\[)\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b"
)

# kernel ktime u uglatim zagradama, npr. [123456.789]
KTIME_BRACKETS_RE = re.compile(r"\[\d+\.\d+]")

DOUBLE_DASH_RE = re.compile(r"\s-\s-")

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SERVER_RE = re.compile(r"\b[A-Za-z0-9_.-]*server\d+\b", re.IGNORECASE)
USER_RE = re.compile(r"\b(?:user[\-_]?\d+|root|admin|guest)\b", re.IGNORECASE)
PID_RE = re.compile(r"([a-zA-Z]+)\[(\d+)\]")
#  Port: dodano \s* nakon sep da uhvati 'Port:' + razmak + broj
PORT_RE = re.compile(r"\b(?P<label>[Pp]ort)(?P<sep>[ =:])(?P<ws>\s*)(?P<num>\d{1,5})\b")


# Učitaj listu JSON objekata iz fajla (svaka linija je jedan JSON)
def load_events(path: str | Path):
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def parse_time(value):
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (ValueError, TypeError):
        pass
    if isinstance(value, str) and value.endswith("+0000"):
        try:
            return datetime.fromisoformat(value[:-5] + "+00:00")
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def extract_front_timestamp(text: str):
    m = FRONT_TIMESTAMP_RE.match(text)
    return m.group(0) if m else None


def get_field(ev: dict, key: str):
    if key in ev:
        return ev[key]
    res = ev.get("result")
    return res.get(key) if isinstance(res, dict) else None


def _lookup(value: str, mapping: dict[str, str], prefix: str):
    if value in mapping:
        return mapping[value]
    label = f"{{{{{prefix}_{len(mapping)+1}}}}}"
    mapping[value] = label
    return label


def placeholderize_text(text: str, ip_map, user_map, srv_map, port_map):
    # IP‑adrese
    text = IP_RE.sub(lambda m: _lookup(m.group(0), ip_map, "HOST"), text)

    # serveri
    text = SERVER_RE.sub(lambda m: _lookup(m.group(0), srv_map, "SERVER"), text)

    # korisnici
    text = USER_RE.sub(lambda m: _lookup(m.group(0), user_map, "USER"), text)

    # PID
    text = PID_RE.sub(lambda m: f"{m.group(1)}[{{{{PID}}}}]", text)

    # portovi
    def port_repl(m):
        label = _lookup(m.group("num"), port_map, "PORT")
        return f"{m.group('label')}{m.group('sep')}{m.group('ws')}{label}"

    text = PORT_RE.sub(port_repl, text)

    return text


def process(events):
    if not events:
        return []

    tuples = []
    for ev in events:
        ts = parse_time(get_field(ev, "_time"))
        tuples.append((ts, ev))

    base_candidates = [t for t, _ in tuples if t is not None]
    base_time = min(base_candidates) if base_candidates else None

    tuples.sort(key=lambda t: t[0] or datetime.max)  # najraniji prvi

    ip_map: dict[str, str] = {}
    user_map: dict[str, str] = {}
    srv_map: dict[str, str] = {}
    port_map: dict[str, str] = {}
    output: list[dict[str, str]] = []

    for ts, ev in tuples:
        raw: str = get_field(ev, "_raw") or ""
        delta = int((ts - base_time).total_seconds()) if (base_time and ts) else 0
        ph_time = "{{NOW}}" if delta == 0 else f"{{{{NOW+{delta}}}}}"

        ft = extract_front_timestamp(raw)
        if ft:
            raw = raw.replace(ft, ph_time, 1)
        else:
            raw = f"{ph_time} {raw}" if raw else ph_time

        raw = APACHE_TS_IN_BRACKETS_RE.sub("", raw)  # [02/Jan/...]
        raw = ISO_TS_IN_BRACKETS_RE.sub(f"[{ph_time}]", raw)  # [2025-...]
        raw = INLINE_ISO_TS_RE.sub("", raw)  # 2025-...Z
        raw = KTIME_BRACKETS_RE.sub("[{{KTIME}}]", raw)  # [123456.789]
        raw = DOUBLE_DASH_RE.sub(" ", raw)  # " - - "

        raw = placeholderize_text(raw, ip_map, user_map, srv_map, port_map)

        raw = INLINE_ISO_TS_RE.sub("", raw)

        raw = re.sub(r"\s{2,}", " ", raw).strip()

        output.append({"line": raw})

    return output


def write_output(lines: list[dict[str, str]], out_path: str | Path):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        for obj in lines:
            json.dump(obj, fh, ensure_ascii=False)
            fh.write("\n")


def main():
    p = argparse.ArgumentParser(
        description="Parametriziraj jedan Splunk JSON log u placeholder‑oblik (kronološki, bez stvarnih datuma)"
    )
    p.add_argument("src", help="Izvorni .json log")
    p.add_argument("--out", help="Izlazni fajl (default: <src>_placeholder.json)")
    ns = p.parse_args()

    src = Path(ns.src)
    if not src.is_file():
        raise SystemExit(f"[GREŠKA] Fajl ne postoji: {src}")

    out_path = Path(ns.out) if ns.out else src.with_stem(f"{src.stem}_placeholder")

    events = load_events(src)
    processed = process(events)
    write_output(processed, out_path)
    print(f"Placeholder log spremljen u: {out_path}")


if __name__ == "__main__":
    main()
