from __future__ import annotations

import argparse
import json
import pathlib
import re
from collections import defaultdict
from datetime import datetime
from typing import Callable, Pattern, Sequence, Tuple

TIMESTAMP_PATTERNS: Sequence[Tuple[Pattern[str], str]] = [
    (re.compile(r"^(\w{3} \d{2} \d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
    (re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})]"), "%Y-%m-%d %H:%M:%S"),
    (re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"), "%d/%b/%Y:%H:%M:%S"),
    (re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"), "%Y-%m-%d %H:%M:%S"),
    # ISO‑8601 with optional trailing Z — Z is **not** part of group(1)
    (re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:Z)?"), "%Y-%m-%dT%H:%M:%S"),
]

RuleFn = Callable[[re.Match[str], dict[str, str], dict[str, int]], str]
RULES: list[tuple[Pattern[str], RuleFn]] = []


def _register(pattern: str, *, flags: int = re.IGNORECASE):
    def decorator(func: RuleFn):
        RULES.append((re.compile(pattern, flags), func))
        return func

    return decorator


def _entity(
    fmt: str,
    match: re.Match[str],
    mapping: dict[str, str],
    counters: dict[str, int],
    etype: str,
) -> str:
    value = match.group(1)
    if value not in mapping:
        counters[etype] += 1
        mapping[value] = fmt % counters[etype]
    return mapping[value]


@_register(r"\bauthserver\b")
def _static_server(match, mapping, counters):
    return "{{SERVER_DB}}"


@_register(r"sshd\[(\d+)]")
def _pid(match, mapping, counters):
    return "sshd[{{PID}}]"


# IPs
@_register(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
def _ipv4(match, mapping, counters):
    return _entity("{{HOST_%d}}", match, mapping, counters, "host")


# Ports – "port 22", "Port=22", "Port:22"
@_register(r"\bPort[ =:](\d+)")
@_register(r"\bport (\d+)")
def _port_any(match, mapping, counters):
    return "port {{PORT}}"


# Emails & users
@_register(r"\buser ([A-Za-z0-9_.+-@]+)|for ([A-Za-z0-9_.+-@]+)")
@_register(r"\bUser=([A-Za-z0-9_.+-@]+)")
@_register(r"\bUSER=([A-Za-z0-9_.+-@]+)")
@_register(r"\bsasl_username=([A-Za-z0-9_.+-@]+)")
@_register(r"from=<([A-Za-z0-9_.+-@]+)>")
def _user_generic(match, mapping, counters):
    user = match.group(1) or match.group(2)
    dummy = re.match(r"(.*)", user)
    return _entity("{{USER_%d}}", dummy, mapping, counters, "user")


@_register(r"to=<([A-Za-z0-9_.+-@]+)>")
@_register(r"TO=<([A-Za-z0-9_.+-@]+)>")
def _target_email(match, mapping, counters):
    return "{{TARGET_EMAIL}}"


@_register(r"invalid user ([A-Za-z0-9_]+)")
def _invalid_user(match, mapping, counters):
    return _entity("{{USER_%d}}", match, mapping, counters, "user")


# Servers
@_register(r"\bDevice=([A-Za-z0-9_-]+)")
@_register(r"\b(server\d+)\b")
def _server_name(match, mapping, counters):
    return _entity("{{SERVER_%d}}", match, mapping, counters, "server")


# Paths, events, threats
@_register(r"\\[A-Z]:\\[^\s\"']+")
def _windows_path(match, mapping, counters):
    return _entity("{{FILE_PATH_%d}}", match, mapping, counters, "fpath")


@_register(r"Event ID:\s*(\d{3,5})")
def _event_id(match, mapping, counters):
    return "{{EVENT_ID}}"


@_register(r"\b(Trojan:[^\s\"']+|Backdoor:[^\s\"']+)\b")
def _threat_name(match, mapping, counters):
    return _entity("{{THREAT_%d}}", match, mapping, counters, "threat")


def _find_ts(line: str) -> tuple[str, str] | None:
    for rx, fmt in TIMESTAMP_PATTERNS:
        m = rx.search(line)
        if m:
            return m.group(1), fmt
    return None


def _process_file(path: pathlib.Path, fout, start_fixed: datetime | None):
    mapping: dict[str, str] = {}
    counters: dict[str, int] = defaultdict(int)
    start_ts: datetime | None = start_fixed

    with path.open("r", encoding="utf-8", errors="ignore") as fin:
        for raw in fin:
            raw = raw.rstrip("\n")
            ts_info = _find_ts(raw)
            if not ts_info:
                continue
            ts_text, ts_fmt = ts_info
            ts_dt = datetime.strptime(ts_text, ts_fmt)
            if start_ts is None:
                start_ts = ts_dt
            delta = int((ts_dt - start_ts).total_seconds())
            line = raw.replace(ts_text, f"{{{{NOW+{delta}}}}}")
            for rx, fn in RULES:
                line = rx.sub(lambda m: fn(m, mapping, counters), line)
            json.dump({"line": line}, fout, ensure_ascii=False)
            fout.write("\n")


def _parse_args():
    p = argparse.ArgumentParser(description="Convert logs→placeholder JSONL")
    p.add_argument("-i", "--input", required=True, help="Log file or directory")
    p.add_argument(
        "-o", "--output", default="out/placeholder_logs.jsonl", help="Destination JSONL"
    )
    p.add_argument(
        "-s", "--start", default=None, help="Optional fixed reference timestamp"
    )
    p.add_argument(
        "--recursive", action="store_true", help="Recurse into sub-directories"
    )
    return p.parse_args()


def _parse_start(text: str | None) -> datetime | None:
    if text is None:
        return None
    for _, fmt in TIMESTAMP_PATTERNS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        raise SystemExit(f'Cannot parse --start "{text}"')


def main():
    args = _parse_args()
    start_fixed = _parse_start(args.start)
    in_path = pathlib.Path(args.input)
    out_path = pathlib.Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    paths = (
        in_path.rglob("*.txt")
        if in_path.is_dir() and args.recursive
        else (in_path.glob("*.txt") if in_path.is_dir() else [in_path])
    )

    with out_path.open("w", encoding="utf-8") as fout:
        for p in paths:
            _process_file(p, fout, start_fixed)

    print(f"Processed {len(list(paths))} file(s) → {out_path}")


if __name__ == "__main__":
    main()
