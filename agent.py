import concurrent.futures
import csv
import ipaddress
import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, request, make_response

HERE = Path(__file__).resolve().parent
TRUSTED_FILE = HERE / "trusted_devices.json"
SEEN_FILE = HERE / "known_devices.json"
LOG_FILE = HERE / "security_events.csv"
SCAN_SECONDS = 30
MAX_HOSTS = 512

app = Flask(__name__)
lock = threading.Lock()
state = {"gateway": "192.168.0.1", "network": "Not scanned",
         "devices": [], "events": [], "last_scan": None}


def timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_json(path, data):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def add_event(title, details="", severity="normal"):
    event = {"time": timestamp(), "title": title,
             "details": details, "severity": severity}
    events = load_json(LOG_FILE.with_suffix(".json"), [])
    events.append(event)
    events = events[-200:]
    save_json(LOG_FILE.with_suffix(".json"), events)
    state["events"] = events


def get_network():
    result = subprocess.run(["ipconfig"], capture_output=True, text=True,
                            errors="replace", timeout=10)
    for block in re.split(r"\r?\n\s*\r?\n", result.stdout):
        ipm = re.search(r"IPv4 Address[.\s]*:\s*([\d.]+)", block, re.I)
        mm = re.search(r"Subnet Mask[.\s]*:\s*([\d.]+)", block, re.I)
        gm = re.search(r"Default Gateway[.\s]*:\s*([\d.]+)", block, re.I)
        if not (ipm and mm and gm):
            continue
        ip, mask, gateway = ipm.group(1), mm.group(1), gm.group(1)
        try:
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            if (ipaddress.ip_address(ip).is_global or ip.startswith("169.254.")
                    or net.prefixlen < 16 or net.num_addresses - 2 > MAX_HOSTS):
                continue
            if ipaddress.ip_address(gateway) in net:
                return ip, gateway, net
        except ValueError:
            continue
    raise RuntimeError("Could not detect a small private IPv4 network. Check Wi-Fi and run ipconfig.")


def ping(ip):
    try:
        subprocess.run(["ping", "-n", "1", "-w", "300", ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass


def scan():
    local_ip, gateway, network = get_network()
    hosts = [str(ip) for ip in network.hosts() if str(ip) != local_ip]
    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
        list(pool.map(ping, hosts))
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                            errors="replace", timeout=10)
    pattern = re.compile(r"^\s*([\d.]+)\s+([0-9a-f-]{17})\s+(\w+)", re.I)
    trusted = set(load_json(TRUSTED_FILE, []))
    old = load_json(SEEN_FILE, {})
    found = {}
    for line in result.stdout.splitlines():
        m = pattern.match(line)
        if not m:
            continue
        ip, mac, kind = m.groups()
        try:
            if ipaddress.ip_address(ip) not in network:
                continue
        except ValueError:
            continue
        mac = mac.lower().replace("-", ":")
        if mac == "ff:ff:ff:ff:ff:ff":
            continue
        found[mac] = {"ip": ip, "mac": mac, "type": kind,
                      "trusted": mac in trusted, "hostname": ""}
    for mac, d in found.items():
        if mac not in old:
            if load_json(SEEN_FILE, None) is not None:
                # First scan establishes a baseline; later new MACs are logged.
                if old:
                    add_event("Unknown device discovered", f"{d['ip']} · {mac}",
                              "high" if mac not in trusted else "normal")
            old[mac] = {"ip": d["ip"], "last_seen": timestamp()}
        else:
            old[mac] = {"ip": d["ip"], "last_seen": timestamp()}
    save_json(SEEN_FILE, old)
    with lock:
        state.update({"gateway": gateway, "network": str(network),
                      "devices": sorted(found.values(), key=lambda d: tuple(map(int, d["ip"].split(".")))),
                      "last_scan": timestamp()})
    return len(found)


def scanner_loop():
    while True:
        try:
            scan()
        except Exception as exc:
            add_event("Monitoring error", str(exc), "normal")
        time.sleep(SCAN_SECONDS)


@app.after_request
def cors(response):
    # Local dashboard access only; no credentials are accepted by this API.
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/status", methods=["GET", "OPTIONS"])
def status():
    if request.method == "OPTIONS":
        return make_response("", 204)
    with lock:
        return jsonify({**state, "events": load_json(LOG_FILE.with_suffix(".json"), [])[-30:]})


@app.route("/api/trust", methods=["POST", "OPTIONS"])
def trust():
    if request.method == "OPTIONS":
        return make_response("", 204)
    body = request.get_json(silent=True) or {}
    mac = str(body.get("mac", "")).lower().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        return jsonify({"error": "Invalid MAC address"}), 400
    trusted = set(load_json(TRUSTED_FILE, []))
    trusted.add(mac)
    save_json(TRUSTED_FILE, sorted(trusted))
    add_event("Device marked trusted", mac)
    with lock:
        for d in state["devices"]:
            d["trusted"] = d["mac"] in trusted
    return jsonify({"ok": True, "mac": mac})


if __name__ == "__main__":
    if not TRUSTED_FILE.exists():
        save_json(TRUSTED_FILE, [])
    if not SEEN_FILE.exists():
        save_json(SEEN_FILE, {})
    if not LOG_FILE.with_suffix(".json").exists():
        save_json(LOG_FILE.with_suffix(".json"), [])
    threading.Thread(target=scanner_loop, daemon=True).start()
    # Local-only API. Do not expose this server to the public internet.
    app.run(host="127.0.0.1", port=8765, debug=False, use_reloader=False)
