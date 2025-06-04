import socket
import time
import threading
import json

# Global variables to store configuration
config = {
    "logs_file": "logs_file.txt",
    "splunk_host": "splunk-enterprise",
    "tcp_port": 15140,
    "udp_port": 1514,
    "splunkUF": False,
    "protocol": "tcp",
    "running": False,
    "Brute_force_login": False,
    "Execute_and_create_mal": False,
    "Connection": False,
    "Win_def": False,
    "Email": False,
    "FireWall": False,
    "Web_server": False,
    "Privilege_escalation": False,
    "DNS_query": False,
    "Authentication": False,
    "malicious_ip": "123.123.123.123",
    "malicious_user": "user01",
    "Noise": False,
}

LogsDict = {
    "Brute_force_login": "Logovi_za_prikaz/Login_logs.txt",
    "Execute_and_create_mal": "Logovi_za_prikaz/Eventlog_exe_create_logs.txt",
    "Connection": "Logovi_za_prikaz/Connection_logs.txt",
    "Win_def": "Logovi_za_prikaz/Security_alert_win_def_logs.txt",
    "Email": "Drugi_napad_logovi/Email_logs.txt",
    "FireWall": "Drugi_napad_logovi/Firewall_logs.txt",
    "Web_server": "Drugi_napad_logovi/Web_server_logs.txt",
    "Privilege_escalation": "Drugi_napad_logovi/Privilege_escalation_logs.txt",
    "DNS_query": "Drugi_napad_logovi/DNS_query_logs.txt",
    "Noise": "Logovi_za_prikaz/Noise_logs.txt",
    "Authentication": "Drugi_napad_logovi/Authentication_logs.txt",
}

# Lock for thread-safe configuration updates
config_lock = threading.Lock()


def changeLine(line):
    with config_lock:
        malicious_ip = config["malicious_ip"]
        malicious_user = config["malicious_user"]
    return line.replace("<MALICIOUS_IP>", malicious_ip).replace(
        "<MALICIOUS_USER>", malicious_user
    )


def send_noise_logs():
    """Function to send noise logs over UDP."""
    with config_lock:
        splunk_host = config["splunk_host"]
        udp_port = config["udp_port"]
        noise_log_file = LogsDict["Noise"]

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with open(noise_log_file, "r") as f:
            for line in f:
                if not config["running"]:
                    break
                sock.sendto(line.encode(), (splunk_host, udp_port))
                time.sleep(0.2)  # Simulate real-time log sending
        sock.close()
    except Exception as e:
        print(f"Error sending noise logs: {e}")


def send_logs_to_splunk():
    with config_lock:
        splunk_host = config["splunk_host"]
        protocol = config["protocol"]
        tcp_port = config["tcp_port"]
        udp_port = config["udp_port"]
        splunkUF = config["splunkUF"]

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM,
        )
        port = tcp_port if protocol == "tcp" else udp_port
        if protocol == "tcp" and not splunkUF:
            sock.connect((splunk_host, port))
        elif protocol == "udp" and not splunkUF:
            sock.connect((splunk_host, port))
        elif splunkUF:
            with open("/Logovi_za_prikaz/splunkUF.txt", "w") as file:
                for key in LogsDict:
                    if key == "Noise":  # Skip noise logs here, handled separately
                        continue
                    with config_lock:
                        if config.get(key, False):
                            file_path = LogsDict[key]

                    with open(file_path, "r") as f:
                        for line in f:
                            newline = changeLine(line)
                            file.write(newline)
                file.close()
        if not splunkUF:
            for key in LogsDict:
                if key == "Noise":  # Skip noise logs here, handled separately
                    continue
                with config_lock:
                    if config.get(key, False):
                        file_path = LogsDict[key]

                with open(file_path, "r") as f:
                    for line in f:
                        newline = changeLine(line)
                        if not config["running"]:
                            break
                        if protocol == "tcp":
                            sock.sendall(newline.encode())
                        elif protocol == "udp":
                            sock.sendto(newline.encode(), (splunk_host, port))
                        time.sleep(0.1)
        sock.close()
    except Exception as e:
        print(f"Error sending logs to Splunk: {e}")


def process_command(command):
    cmd = command.get("command")
    params = command.get("params", [])

    if cmd == "SET":
        if isinstance(params, list):
            with config_lock:
                for param in params:
                    variable = param.get("variable")
                    value = param.get("value")
                    if variable in config:
                        config[variable] = value
                        print(f"Configuration updated: {variable} = {value}")
                    else:
                        print(f"Unknown configuration variable: {variable}")
        else:
            print("Invalid SET command format. 'params' should be a list of variables.")

    elif cmd == "START":
        with config_lock:
            if not config["running"]:
                config["running"] = True
                threading.Thread(target=send_logs_to_splunk, daemon=True).start()
                if config["Noise"]:  # Start noise logs if enabled
                    threading.Thread(target=send_noise_logs, daemon=True).start()
                print("Log sending started.")
            else:
                print("Log sending is already running.")

    elif cmd == "STOP":
        with config_lock:
            if config["running"]:
                config["running"] = False
                print("Log sending stopped.")
            else:
                print("Log sending is not running.")

    elif cmd == "HELP":
        print(
            """
Available commands:
- SET [{"variable": "<variable_name>", "value": "<value>"}, ...]
- START
- STOP
- EXIT
- HELP
        """
        )

    elif cmd == "EXIT":
        exit()

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    print('Use {"command": "HELP"} to see available commands.')
    print(
        "Awaiting commands. Use SET, START, STOP, HELP, or EXIT to control the program."
    )

    while True:
        try:
            user_input = input("Enter command: ")
            command = json.loads(user_input)
            process_command(command)
        except json.JSONDecodeError:
            print("Invalid command format. Please provide a valid JSON command.")
        except KeyboardInterrupt:
            print("\nExiting program.")
            break
