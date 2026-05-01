#!/usr/bin/env python3
"""
Pi-hole Dashboard — Flask Backend
Run with: sudo python3 App.py
"""
 
import os
import json
import time
import sqlite3
import subprocess
import threading
import ipaddress
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
 
from flask import Flask, jsonify, Response, request, stream_with_context
 
# ─────────────────────────────────────────────
# ROOT PRIVILEGE CHECK
# ─────────────────────────────────────────────
if os.geteuid() != 0:
    print("=" * 60)
    print("  WARNING: Not running as root.")
    print("  iptables block/unblock will FAIL silently.")
    print("  Run with: sudo python3 App.py")
    print("=" * 60)
 
app = Flask(__name__)
 
DB_PATH = "pihole-FTL.db"
BLOCKED_CLIENTS_FILE = "blocked_clients.json"
 
# ─────────────────────────────────────────────
# WATCHLIST — domains that trigger alerts
# ─────────────────────────────────────────────
WATCHLIST = {
    "chat.openai.com",
    "chatgpt.com",
    "openai.com",
    "tiktok.com",
    "www.tiktok.com",
}
 
BLOCKED_STATUSES = {1, 5, 6, 7, 8, 9, 12}
 
STATUS_LABELS = {
    1:  "Blocked (Gravity)",
    2:  "Allowed (Forwarded)",
    3:  "Allowed (Cache)",
    4:  "Allowed (Forwarded)",
    5:  "Blocked (Upstream)",
    6:  "Blocked (Regex)",
    7:  "Blocked (Denylist)",
    8:  "Blocked (External IP)",
    9:  "Blocked (Regex/Gravity)",
    10: "Allowed (Retried)",
    14: "Retried",
    16: "Cache Expired",
    17: "Cached (Stale)",
}
 
# ─────────────────────────────────────────────
# THREAD LOCKS
# ─────────────────────────────────────────────
subscriber_lock = threading.Lock()
watchlist_lock  = threading.Lock()
blocked_lock    = threading.Lock()
 
alert_subscribers = []
stats_subscribers = []
 
# ─────────────────────────────────────────────
# PERSISTENT BLOCKED CLIENTS
# Loaded from disk on startup, re-applied via
# iptables so blocks survive a Flask restart.
# ─────────────────────────────────────────────
def load_blocked_clients() -> set:
    """Load persisted blocked IPs from disk."""
    try:
        if Path(BLOCKED_CLIENTS_FILE).exists():
            with open(BLOCKED_CLIENTS_FILE) as f:
                data = json.load(f)
                return set(data.get("blocked", []))
    except Exception as e:
        print(f"[blocked_clients] Failed to load: {e}")
    return set()
 
 
def save_blocked_clients():
    """Write current blocked set to disk (call inside blocked_lock)."""
    try:
        with open(BLOCKED_CLIENTS_FILE, "w") as f:
            json.dump({"blocked": sorted(blocked_clients)}, f)
    except Exception as e:
        print(f"[blocked_clients] Failed to save: {e}")
 
 
def reapply_iptables_rules():
    """
    On startup, re-apply iptables rules for all persisted blocked IPs.
    Checks whether each rule already exists before inserting.
    """
    for ip in list(blocked_clients):
        for proto in ("udp", "tcp"):
            _iptables_insert_if_missing(ip, proto)
    if blocked_clients:
        print(f"[*] Re-applied iptables rules for {len(blocked_clients)} blocked client(s)")
 
 
blocked_clients: set = load_blocked_clients()
 
 
# ─────────────────────────────────────────────
# IPTABLES HELPERS
# ─────────────────────────────────────────────
def _validate_ip(ip: str):
    """
    Validate that the string is a legitimate IPv4 or IPv6 address.
    Raises ValueError if not.
    """
    ipaddress.ip_address(ip)  # raises ValueError on bad input
 
 
def _rule_exists(ip: str, proto: str) -> bool:
    """Return True if an iptables INPUT DROP rule already exists for this ip+proto."""
    result = subprocess.run(
        ["iptables", "-C", "DOCKER-USER", "-s", ip, "-p", proto,
         "--dport", "53", "-j", "DROP"],
        capture_output=True, text=True
    )
    return result.returncode == 0
 
 
def _iptables_insert_if_missing(ip: str, proto: str) -> tuple[bool, str]:
    """
    Insert an iptables rule only if it doesn't already exist.
    Returns (success, error_message).
    """
    if _rule_exists(ip, proto):
        return True, ""
    result = subprocess.run(
        ["iptables", "-I", "DOCKER-USER", "-s", ip, "-p", proto,
         "--dport", "53", "-j", "DROP"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode != 0:
        return False, result.stderr.strip()
    return True, ""
 
 
def _iptables_delete_if_exists(ip: str, proto: str) -> tuple[bool, str]:
    """
    Delete an iptables rule only if it exists.
    Returns (success, error_message).
    """
    if not _rule_exists(ip, proto):
        return True, ""   # already gone, that's fine
    result = subprocess.run(
        ["iptables", "-D", "DOCKER-USER", "-s", ip, "-p", proto,
         "--dport", "53", "-j", "DROP"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode != 0:
        return False, result.stderr.strip()
    return True, ""
 
 
# ─────────────────────────────────────────────
# SSE HELPERS
# ─────────────────────────────────────────────
def push_to_all(subscribers, payload):
    with subscriber_lock:
        dead = []
        for q in subscribers:
            try:
                q.append(payload)
            except Exception:
                dead.append(q)
        for d in dead:
            if d in subscribers:
                subscribers.remove(d)
 
 
# ─────────────────────────────────────────────
# DB HELPER
# ─────────────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=2)
    conn.text_factory = lambda b: b.decode(errors="replace")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
    return conn
 
 
# ─────────────────────────────────────────────
# STATS QUERY
# ─────────────────────────────────────────────
def get_stats_data():
    conn = get_conn()
    try:
        cur = conn.cursor()
 
        cur.execute("SELECT COUNT(*) FROM queries")
        total = cur.fetchone()[0]
 
        bs = ','.join(str(s) for s in BLOCKED_STATUSES)
 
        cur.execute(f"SELECT COUNT(*) FROM queries WHERE status IN ({bs})")
        blocked = cur.fetchone()[0]
 
        cur.execute("SELECT COUNT(DISTINCT client) FROM queries")
        clients = cur.fetchone()[0]
 
        cur.execute("SELECT COUNT(DISTINCT domain) FROM queries")
        domains = cur.fetchone()[0]
 
        cur.execute(f"""
            SELECT domain, COUNT(*) as cnt FROM queries
            WHERE status IN ({bs})
            GROUP BY domain ORDER BY cnt DESC LIMIT 10
        """)
        top_blocked = [{"domain": r["domain"], "count": r["cnt"]} for r in cur.fetchall()]
 
        cur.execute(f"""
            SELECT domain, COUNT(*) as cnt FROM queries
            WHERE status NOT IN ({bs})
            AND domain NOT LIKE '%.in-addr.arpa'
            AND domain NOT LIKE '%.arpa'
            GROUP BY domain ORDER BY cnt DESC LIMIT 10
        """)
        top_allowed = [{"domain": r["domain"], "count": r["cnt"]} for r in cur.fetchall()]
 
        cur.execute("""
            SELECT client, COUNT(*) as total FROM queries
            GROUP BY client ORDER BY total DESC LIMIT 10
        """)
        all_clients = {r["client"]: r["total"] for r in cur.fetchall()}
 
        cur.execute(f"""
            SELECT client, COUNT(*) as blocked FROM queries
            WHERE status IN ({bs}) GROUP BY client
        """)
        blocked_by_client = {r["client"]: r["blocked"] for r in cur.fetchall()}
 
        client_data = [
            {
                "client": ip,
                "total": total_count,
                "blocked": blocked_by_client.get(ip, 0),
                "allowed": total_count - blocked_by_client.get(ip, 0)
            }
            for ip, total_count in all_clients.items()
        ]
 
        cur.execute("SELECT status, COUNT(*) as cnt FROM queries GROUP BY status ORDER BY cnt DESC")
        status_dist = [
            {"label": STATUS_LABELS.get(r["status"], f"Status {r['status']}"), "count": r["cnt"]}
            for r in cur.fetchall()
        ]
 
        cur.execute("""
            SELECT CAST(timestamp/3600 AS INTEGER)*3600 as hour_ts, status, COUNT(*) as cnt
            FROM queries GROUP BY hour_ts, status ORDER BY hour_ts
        """)
        timeline = defaultdict(lambda: {"allowed": 0, "blocked": 0})
        for r in cur.fetchall():
            ts = r["hour_ts"]
            if r["status"] in BLOCKED_STATUSES:
                timeline[ts]["blocked"] += r["cnt"]
            else:
                timeline[ts]["allowed"] += r["cnt"]
 
        timeline_data = [
            {
                "timestamp": ts,
                "label": datetime.fromtimestamp(ts).strftime("%m/%d %H:%M"),
                "allowed": v["allowed"],
                "blocked": v["blocked"]
            }
            for ts, v in sorted(timeline.items())
        ]
 
        cur.execute("""
            SELECT timestamp, domain, client, status FROM queries
            ORDER BY timestamp DESC LIMIT 50
        """)
        recent = [
            {
                "time": datetime.fromtimestamp(r["timestamp"]).strftime("%H:%M:%S"),
                "domain": r["domain"],
                "client": r["client"],
                "status": STATUS_LABELS.get(r["status"], f"Status {r['status']}"),
                "blocked": r["status"] in BLOCKED_STATUSES
            }
            for r in cur.fetchall()
        ]
 
        with watchlist_lock:
            wl = sorted(WATCHLIST)
 
        with blocked_lock:
            bc = sorted(blocked_clients)
 
        return {
            "total": total,
            "blocked": blocked,
            "allowed": total - blocked,
            "block_rate": round(blocked / total * 100, 1) if total else 0,
            "unique_clients": clients,
            "unique_domains": domains,
            "top_blocked": top_blocked,
            "top_allowed": top_allowed,
            "client_data": client_data,
            "status_dist": status_dist,
            "timeline": timeline_data,
            "recent": recent,
            "watchlist": wl,
            "blocked_clients": bc,
        }
    finally:
        conn.close()
 
 
# ─────────────────────────────────────────────
# WATCHER THREAD
# ─────────────────────────────────────────────
def watcher():
    print("[*] Watcher started — polling DB for watchlist hits")
 
    last_id = 0
    try:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT MAX(id) FROM queries")
            row = cur.fetchone()
            last_id = row[0] if row[0] else 0
            print(f"[*] Watermark set at query ID {last_id}")
        finally:
            conn.close()
    except Exception as e:
        print(f"[watcher init error] {e}")
 
    last_stats_push = 0.0
    STATS_DEBOUNCE = 2.0
 
    while True:
        try:
            conn = get_conn()
            try:
                cur = conn.cursor()
 
                with watchlist_lock:
                    wl_domains = list(WATCHLIST)
 
                if wl_domains:
                    # Use proper parameterized placeholders for the IN clause
                    placeholders = ','.join('?' for _ in wl_domains)
                    cur.execute(
                        f"""
                        SELECT id, timestamp, domain, client, status
                        FROM queries
                        WHERE id > ? AND domain IN ({placeholders})
                        ORDER BY id ASC
                        """,
                        (last_id, *wl_domains)
                    )
                    for row in cur.fetchall():
                        last_id = max(last_id, row["id"])
                        alert = {
                            "id": row["id"],
                            "timestamp": datetime.fromtimestamp(row["timestamp"]).strftime("%H:%M:%S"),
                            "domain": row["domain"],
                            "client": row["client"],
                            "blocked": row["status"] in BLOCKED_STATUSES,
                        }
                        print(f"[!] WATCHLIST HIT: {row['client']} → {row['domain']}")
                        push_to_all(alert_subscribers, alert)
            finally:
                conn.close()
 
            now = time.time()
            if now - last_stats_push >= STATS_DEBOUNCE:
                last_stats_push = now
                push_to_all(stats_subscribers, get_stats_data())
 
        except Exception as e:
            print(f"[watcher error] {e}")
 
        time.sleep(2)
 
 
# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────
@app.route("/")
def index():
    with open("index.html") as f:
        return f.read()
 
 
@app.route("/api/stats")
def stats():
    return jsonify(get_stats_data())
 
 
@app.route("/api/blocked-clients")
def get_blocked_clients():
    with blocked_lock:
        return jsonify({"blocked_clients": sorted(blocked_clients)})
 
 
@app.route("/api/stats/stream")
def stats_stream():
    def generate():
        my_queue = []
        with subscriber_lock:
            stats_subscribers.append(my_queue)
        try:
            yield f"data: {json.dumps(get_stats_data())}\n\n"
            while True:
                if my_queue:
                    yield f"data: {json.dumps(my_queue.pop(0))}\n\n"
                else:
                    yield ": heartbeat\n\n"
                time.sleep(0.5)
        except GeneratorExit:
            with subscriber_lock:
                if my_queue in stats_subscribers:
                    stats_subscribers.remove(my_queue)
 
    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
 
 
@app.route("/api/alerts/stream")
def alert_stream():
    def generate():
        my_queue = []
        with subscriber_lock:
            alert_subscribers.append(my_queue)
        try:
            yield "data: {\"type\": \"connected\"}\n\n"
            while True:
                if my_queue:
                    yield f"data: {json.dumps(my_queue.pop(0))}\n\n"
                else:
                    yield ": heartbeat\n\n"
                time.sleep(0.5)
        except GeneratorExit:
            with subscriber_lock:
                if my_queue in alert_subscribers:
                    alert_subscribers.remove(my_queue)
 
    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
 
 
@app.route("/api/action/allow", methods=["POST"])
def action_allow():
    domain = request.json.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "no domain"}), 400
    try:
        # -w is the correct Pi-hole CLI flag for allowlist
        result = subprocess.run(
            ["pihole", "-w", domain],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return jsonify({"error": result.stderr.strip() or "pihole -w failed"}), 500
        return jsonify({"ok": True, "domain": domain, "output": result.stdout.strip()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
 
@app.route("/api/action/block", methods=["POST"])
def action_block():
    client_ip = request.json.get("client", "").strip()
    if not client_ip:
        return jsonify({"error": "no client IP"}), 400
 
    # Validate IP before passing to shell
    try:
        _validate_ip(client_ip)
    except ValueError:
        return jsonify({"error": f"invalid IP address: {client_ip}"}), 400
 
    errors = []
    for proto in ("udp", "tcp"):
        ok, err = _iptables_insert_if_missing(client_ip, proto)
        if not ok:
            errors.append(f"{proto}: {err}")
 
    if errors:
        return jsonify({"error": "; ".join(errors)}), 500
 
    with blocked_lock:
        blocked_clients.add(client_ip)
        save_blocked_clients()
 
    print(f"[block] DNS DROP applied for {client_ip}")
    return jsonify({"ok": True, "client": client_ip})
 
 
@app.route("/api/action/unblock", methods=["POST"])
def action_unblock():
    client_ip = request.json.get("client", "").strip()
    if not client_ip:
        return jsonify({"error": "no client IP"}), 400
 
    try:
        _validate_ip(client_ip)
    except ValueError:
        return jsonify({"error": f"invalid IP address: {client_ip}"}), 400
 
    errors = []
    for proto in ("udp", "tcp"):
        ok, err = _iptables_delete_if_exists(client_ip, proto)
        if not ok:
            errors.append(f"{proto}: {err}")
 
    if errors:
        return jsonify({"error": "; ".join(errors)}), 500
 
    with blocked_lock:
        blocked_clients.discard(client_ip)
        save_blocked_clients()
 
    print(f"[unblock] DNS rules removed for {client_ip}")
    return jsonify({"ok": True, "client": client_ip})
 
 
@app.route("/api/watchlist/add", methods=["POST"])
def watchlist_add():
    domain = request.json.get("domain", "").strip().lower()
    if domain:
        with watchlist_lock:
            WATCHLIST.add(domain)
    with watchlist_lock:
        wl = sorted(WATCHLIST)
    return jsonify({"ok": True, "watchlist": wl})
 
 
@app.route("/api/watchlist/remove", methods=["POST"])
def watchlist_remove():
    domain = request.json.get("domain", "").strip().lower()
    with watchlist_lock:
        WATCHLIST.discard(domain)
        wl = sorted(WATCHLIST)
    return jsonify({"ok": True, "watchlist": wl})
 
 
# ─────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────
if __name__ == "__main__":
    reapply_iptables_rules()
 
    t = threading.Thread(target=watcher, daemon=True)
    t.start()
 
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)