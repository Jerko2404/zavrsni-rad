import json
import os
import socket
import sys
import time
import datetime
from pathlib import Path

import pika

# ───── Configuration ─────────────────────────────────────────────────────────
RABBIT_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBIT_PORT = int(os.getenv("RABBITMQ_PORT", 5672))
RABBIT_USER = os.getenv("RABBITMQ_USER", "admin")
RABBIT_PASS = os.getenv("RABBITMQ_PASS", "admin")
QUEUE_NAME = os.getenv("RABBITMQ_QUEUE", "log_queue")

DEST_HOST = os.getenv("DEST_HOST", "splunk-enterprise")
UDP_PORT = int(os.getenv("UDP_PORT", 1514))
TCP_PORT = int(os.getenv("TCP_PORT", 15140))
UF_PATH = Path(os.getenv("UF_PATH", "/splunkuf/splunkUF.txt"))
UF_PATH.parent.mkdir(parents=True, exist_ok=True)


# ───── send helpers ────────────────────────────────────────────────────────────
def send_udp(line):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(line.encode(), (DEST_HOST, UDP_PORT))


def send_tcp(line):
    with socket.create_connection((DEST_HOST, TCP_PORT), timeout=5) as s:
        s.sendall(line.encode() + b"\n")


def send_uf(line):
    with open(UF_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def deliver(line, proto, *_):
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    final = f"{stamp} {line}"
    if proto == "udp":
        send_udp(final)
    elif proto == "tcp":
        send_tcp(final)
    else:
        send_uf(final)


# ───── Main loop ───────────────────────────────────────────────────────────────
def main():
    # Set to 60 if 30 is not enough
    time.sleep(30)

    creds = pika.PlainCredentials(RABBIT_USER, RABBIT_PASS)
    params = pika.ConnectionParameters(
        host=RABBIT_HOST,
        port=RABBIT_PORT,
        credentials=creds,
        heartbeat=0,  # disable heartbeats
    )

    conn = pika.BlockingConnection(params)
    ch = conn.channel()

    # Create queue to prevent crash
    ch.queue_declare(queue=QUEUE_NAME, durable=False)

    ch.basic_qos(prefetch_count=1)
    last_delay = 0.0
    print("[log_sender] Ready, waiting for messages…")

    try:
        while True:
            method, props, body = ch.basic_get(queue=QUEUE_NAME, auto_ack=False)
            if method is None:
                time.sleep(1)
                continue

            msg = json.loads(body)
            this_delay = float(msg.get("delay_seconds", 0))
            line = msg.get("line", "").strip()
            proto = msg.get("protocol", "udp")

            gap = max(0.0, this_delay - last_delay)
            if gap > 0:
                time.sleep(gap)

            try:
                deliver(line, proto)
            except Exception as e:
                print(f"[ERROR] deliver failed: {e}", file=sys.stderr)

            ch.basic_ack(delivery_tag=method.delivery_tag)
            last_delay = this_delay

    except KeyboardInterrupt:
        print("\n[log_sender] Interrupted, exiting…")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
