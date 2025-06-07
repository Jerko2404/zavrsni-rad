import datetime
import ipaddress
import json
import os
import random
import re
import sys
import threading
import time
from pathlib import Path

import pika

# ───────────── constants & attack-ordering ─────────────────────────────────────────
LOGS_DICT = {
    "Brute_force_login": "Logovi/Prvi/Login_logs_placeholder.json",
    "Execute_and_create_mal": "Logovi/Prvi/Eventlog_exe_create_logs_placeholder.json",
    "Privilege_escalation": "Logovi/Drugi/Privilege_escalation_logs_placeholder.json",
    "Authentication": "Logovi/Drugi/Authentication_logs_placeholder.json",
    "Connection": "Logovi/Prvi/Connection_logs_placeholder.json",
    "DNS_query": "Logovi/Drugi/DNS_query_logs_placeholder.json",
    "FireWall": "Logovi/Drugi/Firewall_logs_placeholder.json",
    "Web_server": "Logovi/Drugi/Web_server_logs_placeholder.json",
    "Email": "Logovi/Drugi/Email_logs_placeholder.json",
    "Win_def": "Logovi/Prvi/Security_alert_win_def_logs_placeholder.json",
    "Noise": "Logovi/Prvi/Noise_logs_placeholder.json",
}

CATEGORY_ORDER = [
    "Brute_force_login",
    "Execute_and_create_mal",
    "Privilege_escalation",
    "Authentication",
    "Connection",
    "DNS_query",
    "FireWall",
    "Web_server",
    "Email",
    "Win_def",
    "Noise",
]

PLACE_RE = re.compile(r"\{\{([^}]+)\}\}")
NOW_PLUS_RE = re.compile(r"NOW\+(\d+)")

PRIVATE_NETS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]
DEFAULT_PORT_RANGE = (1024, 65000)
DEFAULT_PID_RANGE = (1000, 65000)

# ───────────── global configuration ───────────────────────────────────────────────
conf_lock = threading.Lock()
conf = {
    # RabbitMQ – overload via docker-compose env
    "rabbit_host": os.getenv("RABBITMQ_HOST", "rabbitmq"),
    "rabbit_port": int(os.getenv("RABBITMQ_PORT", 5672)),
    "rabbit_user": os.getenv("RABBITMQ_USER", "admin"),
    "rabbit_pass": os.getenv("RABBITMQ_PASS", "admin"),
    "queue": os.getenv("RABBITMQ_QUEUE", "log_queue"),
    # Transport protocol: udp | tcp | uf
    "protocol": "udp",
    # Pools for numbered placeholders
    "hosts": [],
    "servers": [],
    "users": [],
    # Runtime control
    "running": False,
    "speed_factor": 1.0,  # >1 = faster; <1 = slower
    # Extra gap (seconds) between categories
    "extra_gap": 1.0,
}
# By default all categories are OFF
for cat in LOGS_DICT:
    conf[cat] = False


# ───────────── placeholder‐generation helpers ─────────────────────────────────────
def gen_ip():
    net = random.choice(PRIVATE_NETS)
    addr = net.network_address + random.randint(1, net.num_addresses - 2)
    return str(ipaddress.IPv4Address(addr))


def gen_server():
    return "server%02d" % random.randint(1, 99)


def gen_user():
    return "user%02d" % random.randint(1, 99)


def ensure_pool(pool_name, idx, generator):
    lst = conf[pool_name]
    while len(lst) <= idx:
        lst.append(generator())
    return lst[idx]


boot_monotonic = time.monotonic()


# ───────────── token replacement ───────────────────
def replace_tokens(line):

    def repl(match):
        tok = match.group(1)

        # HOST_n
        if tok.startswith("HOST_"):
            i = int(tok.split("_")[1]) - 1
            return ensure_pool("hosts", i, gen_ip)

        # SERVER_n
        if tok.startswith("SERVER_"):
            i = int(tok.split("_")[1]) - 1
            return ensure_pool("servers", i, gen_server)

        # USER_n
        if tok.startswith("USER_"):
            i = int(tok.split("_")[1]) - 1
            return ensure_pool("users", i, gen_user)

        # PORT_n
        if tok.startswith("PORT"):
            return str(random.randint(*DEFAULT_PORT_RANGE))

        # PID
        if tok.startswith("PID"):
            return str(random.randint(*DEFAULT_PID_RANGE))

        # KTIME
        if tok == "KTIME":
            elapsed = time.monotonic() - boot_monotonic
            return "%.6f" % elapsed

        # NOW or NOW+X
        if tok == "NOW":
            return ""
        if tok.startswith("NOW+"):
            return ""

        return match.group(0)

    return PLACE_RE.sub(repl, line)


# ───────────── rabbitmq setup ───────────────────────────────────────────────────
def open_channel():
    creds = pika.PlainCredentials(conf["rabbit_user"], conf["rabbit_pass"])
    params = pika.ConnectionParameters(
        host=conf["rabbit_host"],
        port=conf["rabbit_port"],
        credentials=creds,
    )
    conn = pika.BlockingConnection(params)
    ch = conn.channel()
    ch.queue_declare(queue=conf["queue"], durable=False)
    return conn, ch


# ───────────── publish logic (uses extracted delay from NOW+X) ────────────────────
def publish_category(
    path: Path, category_name: str, channel, base_offset: float
) -> float:
    max_raw = 0.0
    speed = conf["speed_factor"]
    gap = conf["extra_gap"]

    with open(path, "r", encoding="utf-8") as fd:
        for raw in fd:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                orig_line = obj["line"]
            except (json.JSONDecodeError, KeyError):
                print(f"[WARN] Skipping invalid JSON line in {path}: {raw}")
                continue
            m = NOW_PLUS_RE.search(orig_line)
            if m:
                try:
                    raw_delay = float(m.group(1))
                except ValueError:
                    raw_delay = 0.0
            else:
                raw_delay = 0.0
            if raw_delay > max_raw:
                max_raw = raw_delay

            filled = replace_tokens(orig_line)
            adjusted = (raw_delay + base_offset) / speed

            msg = {
                "delay_seconds": adjusted,
                "line": filled,
                "protocol": conf["protocol"],
                "category": category_name,
            }
            channel.basic_publish(
                exchange="",
                routing_key=conf["queue"],
                body=json.dumps(msg).encode(),
            )

    return max_raw


def process_all_categories(channel):
    base = 0.0
    for cat in CATEGORY_ORDER:
        with conf_lock:
            if not conf.get(cat, False):
                continue

        path = Path(LOGS_DICT[cat])
        if not path.exists():
            print(f"[WARN] Missing file for category '{cat}': {path}")
            continue

        max_raw = publish_category(path, cat, channel, base)
        base = max_raw + conf["extra_gap"]


# ───────────── REPL & menus ─────────────────────────────────────────────────────
def menu_set():
    while True:
        print("\nSET MENU — choose what to change:")
        print("  1) Toggle attack categories")
        print("  2) Transport protocol (udp/tcp/uf)")
        print("  3) Speed factor (>1 = faster, <1 = slower)")
        print("  0) Return to main prompt")
        choice = input("set> ").strip()

        if choice == "1":
            _toggle_attacks()
        elif choice == "2":
            _edit_protocol()
        elif choice == "3":
            _edit_speed()
        elif choice == "0":
            return
        else:
            print("Invalid selection.")


def _toggle_attacks():
    while True:
        with conf_lock:
            print("\nAttack categories (toggle by number):")
            for i, cat in enumerate(CATEGORY_ORDER, 1):
                st = "ON " if conf.get(cat, False) else "OFF"
                print(f"  {i:2d}) [{st}] {cat}")
            print("  0) Done")
        sel = input("cat#> ").strip()
        if sel == "0":
            return
        try:
            idx = int(sel) - 1
            cat = CATEGORY_ORDER[idx]
            with conf_lock:
                conf[cat] = not conf[cat]
                print(f"{cat} → {'ON' if conf[cat] else 'OFF'}")
        except (ValueError, IndexError):
            print("Bad number.")


def _edit_protocol():
    with conf_lock:
        current = conf["protocol"]
    val = input(f"protocol (udp/tcp/uf) [{current}]: ").strip().lower()
    if val in {"udp", "tcp", "uf"}:
        with conf_lock:
            conf["protocol"] = val
    elif val:
        print("Invalid protocol.")


def _edit_speed():
    with conf_lock:
        current = conf["speed_factor"]
    val = input(f"speed_factor [current = {current}]: ").strip()
    if not val:
        return
    try:
        f = float(val)
        if f <= 0:
            raise ValueError
        with conf_lock:
            conf["speed_factor"] = f
            print(f"speed_factor set to {f}")
    except ValueError:
        print("Enter a positive number.")


def print_help():
    print(
        """
help    – show this help text
set     – open configuration menu (categories/protocol/speed)
show    – display current configuration
start   – stream the enabled attack logs
stop    – stop streaming (clear queue processing)
exit    – quit program
"""
    )


def show_conf():
    with conf_lock:
        snap = {k: v for (k, v) in conf.items() if k != "running"}
    print(json.dumps(snap, indent=2))


# ───────────── main loop ───────────────────────────────────────────────────────
def main():
    print("Type 'help' for commands.")
    while True:
        try:
            cmd = input("cmd> ").strip().lower()
            if not cmd:
                continue

            if cmd == "help":
                print_help()

            elif cmd == "set":
                menu_set()

            elif cmd == "show":
                show_conf()

            elif cmd == "start":
                # Prevent double‐starts:
                with conf_lock:
                    if conf["running"]:
                        print("[INFO] Already running.")
                        continue
                    conf["running"] = True

                # Open RabbitMQ and enqueue everything:
                try:
                    conn, ch = open_channel()
                except Exception as e:
                    print(f"[ERROR] Could not open RabbitMQ channel: {e}")
                    with conf_lock:
                        conf["running"] = False
                    continue

                process_all_categories(ch)
                conn.close()

                with conf_lock:
                    conf["running"] = False
                print("[INFO] All categories queued.")

            elif cmd == "stop":
                with conf_lock:
                    if not conf["running"]:
                        print("[INFO] Not currently running.")
                    else:
                        conf["running"] = False
                        print("[INFO] Stopped.")

            elif cmd == "exit":
                with conf_lock:
                    conf["running"] = False
                print("[INFO] Bye.")
                sys.exit(0)

            else:
                print("Unknown command – type 'help' for a list.")

        except KeyboardInterrupt:
            print("\n[INFO] Interrupted – type 'exit' to quit cleanly.")


if __name__ == "__main__":
    main()
