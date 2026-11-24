"""
admin.py - Terminal viewer for the lab administrator.

It does NOT read the database directly. It asks the server over HTTP
(using the admin API key), which is another client-server exchange.

Examples:
  python admin.py status               latest report of each computer
  python admin.py alerts               only computers currently in WARNING
  python admin.py recent --limit 10    last 10 reports (history)
  python admin.py status --watch       refresh every 5 seconds (Ctrl+C to stop)
  python admin.py status --server 192.168.1.10
"""

import argparse
import json
import os
import sys
import time

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUEST_TIMEOUT = 5


def load_config():
    with open(os.path.join(BASE_DIR, "config.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def fetch(base_url, api_key, path):
    """GET a JSON list from the server. Returns None if something went wrong."""
    try:
        response = requests.get(f"{base_url}{path}", headers={"X-API-Key": api_key},
                                timeout=REQUEST_TIMEOUT)
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot connect to {base_url}. Is the server running?")
        return None
    except requests.exceptions.Timeout:
        print("[ERROR] Server timed out.")
        return None
    except requests.exceptions.RequestException as err:
        print(f"[ERROR] Request failed: {err}")
        return None

    if response.status_code == 401:
        print("[ERROR] Admin key rejected (HTTP 401).")
        return None
    if response.status_code != 200:
        print(f"[ERROR] Server returned HTTP {response.status_code}.")
        return None
    return response.json()


def print_table(rows):
    """Print reports as an aligned text table."""
    if not rows:
        print("(no reports to show)")
        return
    header = (f"{'HOST':<18}{'IP':<16}{'CPU%':>6}{'RAM%':>7}{'DISK%':>7}  "
              f"{'STATUS':<9}{'TIME':<20}ISSUES")
    print(header)
    print("-" * len(header) + "-" * 12)
    for r in rows:
        issues = ", ".join(r["issues"]) if r["issues"] else "-"
        print(f"{r['hostname'][:17]:<18}{r['source_ip']:<16}"
              f"{r['cpu_percent']:>6.1f}{r['ram_percent']:>7.1f}{r['disk_percent']:>7.1f}  "
              f"{r['status']:<9}{r['received_at']:<20}{issues}")


def show(args, base_url, api_key):
    """Fetch and print whatever the chosen command asks for."""
    if args.command == "recent":
        rows = fetch(base_url, api_key, f"/api/reports?limit={args.limit}")
        title = f"Last {args.limit} reports (newest first)"
    else:
        rows = fetch(base_url, api_key, "/api/status")
        title = "Latest status of each computer"
        if rows is not None and args.command == "alerts":
            rows = [r for r in rows if r["status"] == "WARNING"]
            title = "Computers needing attention"

    if rows is None:
        return False
    print(f"\n=== {title}  [{time.strftime('%Y-%m-%d %H:%M:%S')}] ===")
    print_table(rows)
    if args.command == "status" and rows:
        bad = sum(1 for r in rows if r["status"] == "WARNING")
        print(f"\nComputers: {len(rows)}   Healthy: {len(rows) - bad}   Warning: {bad}")
    return True


def main():
    config = load_config()
    parser = argparse.ArgumentParser(description="Lab administrator terminal viewer")
    parser.add_argument("command", choices=["status", "alerts", "recent"])
    parser.add_argument("--server", default=config["server_host"])
    parser.add_argument("--port", type=int, default=config["server_port"])
    parser.add_argument("--key", default=config["admin_api_key"])
    parser.add_argument("--limit", type=int, default=20, help="rows for 'recent'")
    parser.add_argument("--watch", action="store_true", help="refresh every 5 seconds")
    args = parser.parse_args()

    base_url = f"http://{args.server}:{args.port}"
    try:
        while True:
            ok = show(args, base_url, args.key)
            if not args.watch:
                sys.exit(0 if ok else 1)
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
