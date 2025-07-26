import configparser
import ipaddress
import json
import os
import random
import re
import threading
import time
from pathlib import Path

import pika

# Const + category
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
    "Email",  # 1. Phishing
    "Web_server",  # 2. Prijava na web
    "Authentication",  # 3. Općenita prijava
    "Brute_force_login",  # 4. Proboj grubom silom
    "Privilege_escalation",  # 5. Povišenje ovlasti
    "Execute_and_create_mal",  # 6. Izvršavanje koda
    "DNS_query",  # 7. Pokušaj komunikacije (DNS)
    "FireWall",  # 8. Blokiranje komunikacije (Firewall)
    "Connection",  # 9. Općenite konekcije
    "Win_def",  # 10. Detekcija na računalu
    "Noise",  # 11. Pozadinski šum
]
NOISE_QUEUE = "noise_queue"

PLACE_RE = re.compile(r"\{\{([^}]+)\}\}")
NOW_PLUS_RE = re.compile(r"NOW\+(\d+)")

OVERRIDE_FILE = Path(os.getenv("PARAM_FILE", "placeholder_inputs.txt"))

PRIVATE_NETS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]
DEFAULT_PORT_RANGE = (1024, 65000)
DEFAULT_PID_RANGE = (1000, 65000)

# Conf
conf_lock = threading.Lock()
conf = {
    "rabbit_host": os.getenv("RABBITMQ_HOST", "rabbitmq"),
    "rabbit_port": int(os.getenv("RABBITMQ_PORT", 5672)),
    "rabbit_user": os.getenv("RABBITMQ_USER", "admin"),
    "rabbit_pass": os.getenv("RABBITMQ_PASS", "admin"),
    "queue": os.getenv("RABBITMQ_QUEUE", "log_queue"),
    "protocol": "udp",  # udp|tcp|uf
    "running": False,
    "speed_factor": 1.0,  # Log sending speed multiplier
    "extra_gap": 1.0,  # Gap between 2 different log categories
    "param_mode": "random",  # random|file
    "param_overrides": {},
}

for c in CATEGORY_ORDER:
    conf[c] = False


# Load from placeholder_inputs.txt
def load_overrides(path):
    cp = configparser.ConfigParser(allow_no_value=True, interpolation=None)
    cp.optionxform = str
    overrides = {}

    if not path.exists():
        print("[WARN] Override file '%s' not found" % path)
        return overrides

    cp.read(path, encoding="utf-8")

    default_bucket = {}
    for key, value in cp.defaults().items():
        if value.strip():
            default_bucket[key] = value
    if default_bucket:
        overrides["DEFAULT"] = default_bucket

    for sec in cp.sections():
        bucket = {}
        for key, value in cp.items(sec, raw=True):
            if value.strip():
                bucket[key] = value
        if bucket:
            overrides[sec] = bucket

    total = sum(len(v) for v in overrides.values())
    print("[INFO] Loaded %d overrides from %s" % (total, path))
    return overrides


# Helpers
def gen_ip():
    net = random.choice(PRIVATE_NETS)
    addr = net.network_address + random.randint(1, net.num_addresses - 2)
    return str(ipaddress.IPv4Address(addr))


def gen_server():
    return "server%02d" % random.randint(1, 99)


def gen_user():
    return "user%02d" % random.randint(1, 99)


_pools = {
    "hosts": [],
    "servers": [],
    "users": [],
}


def pool_get(name, idx, generator):
    lst = _pools[name]
    while len(lst) <= idx:
        lst.append(generator())
    return lst[idx]


boot_time = time.monotonic()


# Placeholder fill
def replace_tokens(line, cat):
    def _repl(match):
        tok = match.group(1)

        if conf["param_mode"] == "file":
            cat_bucket = conf["param_overrides"].get(cat, {})
            if tok in cat_bucket:
                return cat_bucket[tok]
            default_bucket = conf["param_overrides"].get("DEFAULT", {})
            if tok in default_bucket:
                return default_bucket[tok]

        if tok.startswith("HOST_"):
            return pool_get("hosts", int(tok.split("_")[1]) - 1, gen_ip)
        if tok.startswith("SERVER_"):
            return pool_get("servers", int(tok.split("_")[1]) - 1, gen_server)
        if tok.startswith("USER_"):
            return pool_get("users", int(tok.split("_")[1]) - 1, gen_user)
        if tok.startswith("PORT"):
            return str(random.randint(*DEFAULT_PORT_RANGE))
        if tok.startswith("PID"):
            return str(random.randint(*DEFAULT_PID_RANGE))
        if tok == "KTIME":
            return "%.6f" % (time.monotonic() - boot_time)
        if tok.startswith("NOW"):
            return ""
        return match.group(0)

    return PLACE_RE.sub(_repl, line)


# RabbitMQ helpers
def open_channel():
    creds = pika.PlainCredentials(conf["rabbit_user"], conf["rabbit_pass"])
    params = pika.ConnectionParameters(
        host=conf["rabbit_host"], port=conf["rabbit_port"], credentials=creds
    )
    conn = pika.BlockingConnection(params)
    ch = conn.channel()
    ch.queue_declare(queue=conf["queue"], durable=False)
    ch.queue_declare(queue=NOISE_QUEUE, durable=False)
    return conn, ch


# Publish
def publish_category(path, cat, ch, base_offset):
    max_raw = 0.0
    speed = conf["speed_factor"]

    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue

            try:
                obj = json.loads(raw)
                orig_line = obj["line"]
            except Exception:
                continue

            m = NOW_PLUS_RE.search(orig_line)
            raw_delay = 0.0
            if m:
                try:
                    raw_delay = float(m.group(1))
                except ValueError:
                    raw_delay = 0.0

            if raw_delay > max_raw:
                max_raw = raw_delay

            payload = {
                "delay_seconds": (raw_delay + base_offset) / speed,
                "line": replace_tokens(orig_line, cat),
                "protocol": conf["protocol"],
                "category": cat,
            }
            out_q = NOISE_QUEUE if cat == "Noise" else conf["queue"]
            ch.basic_publish(
                exchange="", routing_key=out_q, body=json.dumps(payload).encode()
            )

    return max_raw


def enqueue_all(ch):
    base = 0.0
    for cat in CATEGORY_ORDER:
        if cat == "Noise":
            continue
        if not conf[cat]:
            continue
        p = Path(LOGS_DICT[cat])
        if p.exists():
            base = publish_category(p, cat, ch, base) + conf["extra_gap"]

    if conf["Noise"]:
        p_noise = Path(LOGS_DICT["Noise"])
        if p_noise.exists():
            publish_category(p_noise, "Noise", ch, 0.0)


# Menu
def menu_set():
    while True:
        print("\nSET MENU")
        print("  1) Toggle attack categories")
        print("  2) Transport protocol (udp / tcp / uf)")
        print("  3) Speed factor")
        print("  4) Placeholder source (random / file)")
        print("  s) Show current configuration")
        print("  0) Back")
        choice = input("set> ").strip().lower()

        if choice == "1":
            _toggle_categories()
        elif choice == "2":
            _edit_protocol()
        elif choice == "3":
            _edit_speed()
        elif choice == "4":
            _toggle_source()
        elif choice in ("s", "show"):
            show_conf()
        elif choice == "0":
            return
        else:
            print("Invalid selection.")


def _toggle_categories():
    while True:
        for idx, cat in enumerate(CATEGORY_ORDER, 1):
            status = "ON " if conf[cat] else "OFF"
            print("%2d) [%s] %s" % (idx, status, cat))
        print(" 0) Done")
        sel = input("cat#> ").strip()
        if sel == "0":
            return
        if sel.isdigit():
            idx = int(sel) - 1
            if 0 <= idx < len(CATEGORY_ORDER):
                cat = CATEGORY_ORDER[idx]
                conf[cat] = not conf[cat]


def _edit_protocol():
    val = input("protocol (udp/tcp/uf) [%s]: " % conf["protocol"]).strip().lower()
    if val in ("udp", "tcp", "uf"):
        conf["protocol"] = val


def _edit_speed():
    val = input("speed factor [%s]: " % conf["speed_factor"]).strip()
    if not val:
        return
    try:
        conf["speed_factor"] = max(0.01, float(val))
    except ValueError:
        print("Enter a number")


def _toggle_source():
    if conf["param_mode"] == "random":
        ans = input("Switch to FILE mode? [y/N]: ").lower()
        if ans == "y":
            overrides = load_overrides(OVERRIDE_FILE)
            if overrides:
                conf["param_overrides"] = overrides
                conf["param_mode"] = "file"
    else:
        ans = input("Switch to RANDOM mode? [y/N]: ").lower()
        if ans == "y":
            conf["param_mode"] = "random"
            conf["param_overrides"].clear()


# Show/print
def show_conf():
    snap = {}
    for k, v in conf.items():
        if k != "param_overrides":
            snap[k] = v
    print(json.dumps(snap, indent=2))


def print_help():
    print(
        """\
help  - show this help
set   - configuration menu
show  - show current config
start - enqueue logs
stop  - purge RabbitMQ queue & broadcast STOP
exit  - quit
"""
    )


# Main
def main():
    if OVERRIDE_FILE.exists():
        conf["param_overrides"] = load_overrides(OVERRIDE_FILE)
        if conf["param_overrides"]:
            conf["param_mode"] = "file"

    print("Type 'help' for commands.")
    while True:
        try:
            cmd = input("cmd> ").strip().lower()

            if cmd == "help":
                print_help()

            elif cmd == "set":
                menu_set()

            elif cmd == "show":
                show_conf()

            elif cmd == "start":
                if conf["running"]:
                    print("[INFO] Already running")
                    continue
                conn, ch = open_channel()
                enqueue_all(ch)
                conn.close()
                print("[INFO] Logs queued.")

            elif cmd == "stop":
                conn, ch = open_channel()
                for q in (conf["queue"], NOISE_QUEUE):
                    ch.queue_purge(queue=q)
                    ch.basic_publish(
                        exchange="",
                        routing_key=q,
                        body=json.dumps({"control": "STOP"}).encode(),
                    )
                conn.close()
                print("[INFO] Both queues purged and STOP broadcast.")
                conf["running"] = False

            elif cmd == "exit":
                return

        except KeyboardInterrupt:
            print("\nInterrupted - type 'exit' to quit.")


if __name__ == "__main__":
    main()
