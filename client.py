"""
client.py - Runs on each lab computer.

What this program does (in simple words):
  1. Reads this computer's hostname, CPU %, RAM % and disk %  (using psutil).
  2. Sends them to the central server as JSON over HTTP (using requests).
  3. Optionally downloads the approved sample package and VERIFIES its
     SHA-256 checksum. It does NOT install or run the file.

Examples:
  python client.py --once                      send one report to localhost
  python client.py --server 192.168.1.10       send reports to a server on the LAN
  python client.py --count 5 --interval 3      send 5 reports, 3 seconds apart
  python client.py --once --simulate-cpu 95    pretend CPU is 95% (for testing)
  python client.py --download lab_readme.txt   download + verify the sample file
"""

import argparse
import hashlib
import json
import os
import socket
import sys
import time

import psutil
import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_DIR = os.path.join(BASE_DIR, "downloads")
REQUEST_TIMEOUT = 5  # seconds. Without a timeout, a dead server would hang us.


def load_config():
    """Read defaults (port, key, interval) from config.json."""
    with open(os.path.join(BASE_DIR, "config.json"), "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Collecting health information
# ---------------------------------------------------------------------------

def collect_health(sim_cpu=None, sim_ram=None, sim_disk=None):
    """
    Return this computer's health as a dictionary.
    The sim_* values are ONLY for testing: they replace the real reading so
    you can demonstrate warnings without overloading your laptop.
    """
    # interval=1 means "measure CPU over 1 second" (gives a meaningful value)
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    # Root of the main drive: "/" on Linux/Mac, "C:\" on Windows
    disk = psutil.disk_usage(os.path.abspath(os.sep)).percent

    return {
        "hostname": socket.gethostname(),
        "cpu_percent": sim_cpu if sim_cpu is not None else cpu,
        "ram_percent": sim_ram if sim_ram is not None else ram,
        "disk_percent": sim_disk if sim_disk is not None else disk,
    }


# ---------------------------------------------------------------------------
# Talking to the server
# ---------------------------------------------------------------------------

def send_report(base_url, api_key, report):
    """
    POST the report to the server. Returns True if it was accepted.
    All network problems are caught so the program never crashes.
    """
    url = f"{base_url}/api/report"
    headers = {"X-API-Key": api_key}
    try:
        # json=report converts the dictionary to JSON text and sets the
        # header "Content-Type: application/json" automatically.
        response = requests.post(url, json=report, headers=headers,
                                 timeout=REQUEST_TIMEOUT)
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot connect to {base_url}. "
              "Is the server running? Is the IP/port right? Is a firewall blocking it?")
        return False
    except requests.exceptions.Timeout:
        print(f"[ERROR] Server did not answer within {REQUEST_TIMEOUT} seconds.")
        return False
    except requests.exceptions.RequestException as err:
        print(f"[ERROR] Request failed: {err}")
        return False

    if response.status_code == 200:
        body = response.json()
        print(f"[OK] Report accepted. Server says status = {body['status']} "
              f"{body['issues'] if body['issues'] else ''}")
        return True
    if response.status_code == 401:
        print("[ERROR] Server rejected our API key (HTTP 401 Unauthorized).")
    elif response.status_code == 400:
        print(f"[ERROR] Server rejected the data (HTTP 400): {response.text.strip()}")
    else:
        print(f"[ERROR] Unexpected reply: HTTP {response.status_code}")
    return False


def sha256_of_file(path):
    """Calculate the SHA-256 checksum of a local file."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_package(base_url, api_key, name):
    """
    Download an approved package and verify it.
      Step 1 (distribution) : copy the file from server to this computer.
      Step 2 (verification) : compare SHA-256 with the value the server listed.
      Step 3 (installation) : NOT done. This program never runs the file.
    """
    headers = {"X-API-Key": api_key}
    try:
        # Ask the server for the list of packages and the expected checksum.
        listing = requests.get(f"{base_url}/api/packages", headers=headers,
                               timeout=REQUEST_TIMEOUT)
        if listing.status_code != 200:
            print(f"[ERROR] Could not get package list (HTTP {listing.status_code}).")
            return False
        expected = next((p["sha256"] for p in listing.json() if p["name"] == name), None)
        if expected is None:
            print(f"[ERROR] '{name}' is not an approved package.")
            return False

        response = requests.get(f"{base_url}/api/download/{name}", headers=headers,
                                timeout=REQUEST_TIMEOUT)
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot connect to {base_url}. "
              "Is the server running? Is the IP/port right? Is a firewall blocking it?")
        return False
    except requests.exceptions.Timeout:
        print(f"[ERROR] Server did not answer within {REQUEST_TIMEOUT} seconds.")
        return False
    except requests.exceptions.RequestException as err:
        print(f"[ERROR] Download failed: {err}")
        return False

    if response.status_code != 200:
        print(f"[ERROR] Download refused (HTTP {response.status_code}).")
        return False

    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    # os.path.basename stops a malicious name from escaping the folder.
    save_path = os.path.join(DOWNLOAD_DIR, os.path.basename(name))
    with open(save_path, "wb") as f:
        f.write(response.content)
    print(f"[OK] Downloaded to {save_path}  (distribution done)")

    actual = sha256_of_file(save_path)
    if actual == expected:
        print(f"[OK] Checksum matches ({actual[:16]}...)  (verification passed)")
        print("[INFO] File NOT installed or executed. This demo only distributes files.")
        return True
    print("[ERROR] Checksum MISMATCH. File deleted. It may be corrupted or tampered with.")
    os.remove(save_path)
    return False


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------

def parse_args(config):
    parser = argparse.ArgumentParser(description="Lab computer health client")
    parser.add_argument("--server", default=config["server_host"],
                        help="server IP or name (default from config.json)")
    parser.add_argument("--port", type=int, default=config["server_port"],
                        help="server TCP port (default from config.json)")
    parser.add_argument("--key", default=config["client_api_key"],
                        help="client API key (default from config.json)")
    parser.add_argument("--interval", type=float, default=config["report_interval_seconds"],
                        help="seconds between reports")
    parser.add_argument("--count", type=int, default=0,
                        help="number of reports to send (0 = keep going until Ctrl+C)")
    parser.add_argument("--once", action="store_true", help="send one report and exit")
    parser.add_argument("--download", metavar="NAME",
                        help="download and verify an approved package, then exit")
    parser.add_argument("--simulate-cpu", type=float, help="TEST ONLY: fake CPU %%")
    parser.add_argument("--simulate-ram", type=float, help="TEST ONLY: fake RAM %%")
    parser.add_argument("--simulate-disk", type=float, help="TEST ONLY: fake disk %%")
    return parser.parse_args()


def main():
    config = load_config()
    args = parse_args(config)
    # 127.0.0.1 = "this same computer" (localhost). A LAN IP reaches another PC.
    base_url = f"http://{args.server}:{args.port}"

    if args.download:
        ok = download_package(base_url, args.key, args.download)
        sys.exit(0 if ok else 1)

    total = 1 if args.once else args.count
    sent = 0
    try:
        while True:
            report = collect_health(args.simulate_cpu, args.simulate_ram, args.simulate_disk)
            print(f"Sending: CPU={report['cpu_percent']}% RAM={report['ram_percent']}% "
                  f"DISK={report['disk_percent']}% to {base_url}")
            send_report(base_url, args.key, report)
            sent += 1
            if total and sent >= total:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped by user.")


if __name__ == "__main__":
    main()
