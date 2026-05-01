#!/usr/bin/env python3
"""
Pi-hole Dashboard — Flask Backend
Run with: sudo python3 App.py
"""
 
from flask import Flask, jsonify, Response, request, stream_with_context
import sqlite3
import subprocess
import json
import time
import threading
from collections import defaultdict
from datetime import datetime, timezone
 
app = Flask(__name__)
 
DB_PATH = "pihole-FTL.db"
 
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
# SSE — shared subscriber queues
# ─────────────────────────────────────────────
alert_subscribers = []
stats_subscribers = []
subscriber_lock = threading.Lock()
 
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
 
    conn.close()
 
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
        "watchlist": sorted(WATCHLIST),
    }
 
# ─────────────────────────────────────────────
# WATCHER THREAD
# Polls the DB every 2s for new watchlist hits
# and pushes live stats to connected browsers.
# Works on Pi-hole v5 and v6 (no log file needed).
# ─────────────────────────────────────────────
def watcher():
    print("[*] Watcher started — polling DB for watchlist hits")
 
    # Grab the current max row ID as a watermark.
    # Only queries inserted AFTER startup will trigger alerts.
    last_id = 0
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT MAX(id) FROM queries")
        row = cur.fetchone()
        last_id = row[0] if row[0] else 0
        conn.close()
        print(f"[*] Watermark set at query ID {last_id} — watching for new hits only")
    except Exception as e:
        print(f"[watcher init error] {e}")
 
    last_stats_push = 0.0
    STATS_DEBOUNCE = 2.0
 
    while True:
        try:
            conn = get_conn()
            cur = conn.cursor()
 
            # Only look at rows newer than our watermark
            wl = ','.join(f'"{d}"' for d in WATCHLIST)
            if wl:
                cur.execute(f"""
                    SELECT id, timestamp, domain, client, status
                    FROM queries
                    WHERE id > ? AND domain IN ({wl})
                    ORDER BY id ASC
                """, (last_id,))
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
 
            conn.close()
 
            # Push fresh stats (debounced)
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
 
@app.route("/api/stats/stream")
def stats_stream():
    def generate():
        my_queue = []
        with subscriber_lock:
            stats_subscribers.append(my_queue)
        try:
            # Send initial snapshot immediately on connect
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
        result = subprocess.run(["pihole", "allowlist", domain],
                                capture_output=True, text=True, timeout=10)
        return jsonify({"ok": True, "domain": domain, "output": result.stdout.strip()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
@app.route("/api/action/block", methods=["POST"])
def action_block():
    client_ip = request.json.get("client", "").strip()
    if not client_ip:
        return jsonify({"error": "no client IP"}), 400
    try:
        subprocess.run(["iptables", "-I", "FORWARD", "-s", client_ip, "-j", "DROP"],
                       capture_output=True, text=True, timeout=10)
        print(f"[block] iptables DROP {client_ip}")
        return jsonify({"ok": True, "client": client_ip})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
@app.route("/api/action/unblock", methods=["POST"])
def action_unblock():
    client_ip = request.json.get("client", "").strip()
    if not client_ip:
        return jsonify({"error": "no client IP"}), 400
    try:
        subprocess.run(["iptables", "-D", "FORWARD", "-s", client_ip, "-j", "DROP"],
                       capture_output=True, text=True, timeout=10)
        return jsonify({"ok": True, "client": client_ip})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
@app.route("/api/watchlist/add", methods=["POST"])
def watchlist_add():
    domain = request.json.get("domain", "").strip().lower()
    if domain:
        WATCHLIST.add(domain)
    return jsonify({"ok": True, "watchlist": sorted(WATCHLIST)})
 
@app.route("/api/watchlist/remove", methods=["POST"])
def watchlist_remove():
    domain = request.json.get("domain", "").strip().lower()
    WATCHLIST.discard(domain)
    return jsonify({"ok": True, "watchlist": sorted(WATCHLIST)})
 
# ─────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────
if __name__ == "__main__":
    t = threading.Thread(target=watcher, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
    