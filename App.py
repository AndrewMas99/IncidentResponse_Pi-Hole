#!/usr/bin/env python3
"""
Pi-hole Dashboard — Flask Backend with Real-Time Alerts
Run with: sudo python3 App.py
"""
 
from flask import Flask, jsonify, render_template, Response, request
import sqlite3
import subprocess
import json
import time
import threading
from collections import defaultdict
from datetime import datetime
 
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
    # add more here
}
 
BLOCKED_STATUSES = {1, 5, 6, 7, 8, 9, 12}
 
STATUS_LABELS = {
    1: "Blocked (Gravity)",
    2: "Allowed (Forwarded)",
    3: "Allowed (Cache)",
    4: "Allowed (Forwarded)",
    5: "Blocked (Upstream)",
    6: "Blocked (Regex)",
    7: "Blocked (Denylist)",
    8: "Blocked (External IP)",
    9: "Blocked (Regex/Gravity)",
    10: "Allowed (Retried)",
    14: "Retried",
    16: "Cache Expired",
    17: "Cached (Stale)",
}
 
# ─────────────────────────────────────────────
# SSE — alert queue shared across threads
# ─────────────────────────────────────────────
alert_subscribers = []
alert_lock = threading.Lock()
 
def push_alert(alert):
    """Push alert to all connected SSE clients."""
    with alert_lock:
        dead = []
        for q in alert_subscribers:
            try:
                q.append(alert)
            except Exception:
                dead.append(q)
        for d in dead:
            alert_subscribers.remove(d)
 
# ─────────────────────────────────────────────
# WATCHER THREAD — polls DB for watchlist hits
# ─────────────────────────────────────────────
seen_ids = set()
 
def watcher():
    global seen_ids
    print("[*] Watcher thread started")
    # seed seen_ids with existing queries so we don't flood alerts on startup
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM query_storage")
    seen_ids = {r[0] for r in cur.fetchall()}
    conn.close()
    print(f"[*] Seeded {len(seen_ids)} existing query IDs")
 
    while True:
        try:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("""
                SELECT id, timestamp, status, domain, client
                FROM queries
                ORDER BY id DESC
                LIMIT 200
            """)
            rows = cur.fetchall()
            conn.close()
 
            for row in rows:
                qid, ts, status, domain, client = row
                if qid in seen_ids:
                    continue
                seen_ids.add(qid)
 
                if domain and domain.lower().rstrip('.') in WATCHLIST:
                    alert = {
                        "id": qid,
                        "timestamp": datetime.utcfromtimestamp(ts).strftime("%H:%M:%S"),
                        "domain": domain,
                        "client": client,
                        "status": STATUS_LABELS.get(status, f"Status {status}"),
                        "blocked": status in BLOCKED_STATUSES,
                    }
                    print(f"[!] WATCHLIST HIT: {client} → {domain}")
                    push_alert(alert)
 
        except Exception as e:
            print(f"[watcher error] {e}")
 
        time.sleep(3)
 
# ─────────────────────────────────────────────
# DB HELPER
# ─────────────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.text_factory = lambda b: b.decode(errors="replace")
    conn.row_factory = sqlite3.Row
    return conn
 
# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────
@app.route("/")
def index():
    with open("index.html") as f:
        return f.read()
 
@app.route("/api/stats")
def stats():
    conn = get_conn()
    cur = conn.cursor()
 
    cur.execute("SELECT COUNT(*) FROM queries")
    total = cur.fetchone()[0]
 
    cur.execute(f"SELECT COUNT(*) FROM queries WHERE status IN ({','.join(str(s) for s in BLOCKED_STATUSES)})")
    blocked = cur.fetchone()[0]
 
    cur.execute("SELECT COUNT(DISTINCT client) FROM queries")
    clients = cur.fetchone()[0]
 
    cur.execute("SELECT COUNT(DISTINCT domain) FROM queries")
    domains = cur.fetchone()[0]
 
    cur.execute(f"""
        SELECT domain, COUNT(*) as cnt FROM queries
        WHERE status IN ({','.join(str(s) for s in BLOCKED_STATUSES)})
        GROUP BY domain ORDER BY cnt DESC LIMIT 10
    """)
    top_blocked = [{"domain": r["domain"], "count": r["cnt"]} for r in cur.fetchall()]
 
    cur.execute(f"""
        SELECT domain, COUNT(*) as cnt FROM queries
        WHERE status NOT IN ({','.join(str(s) for s in BLOCKED_STATUSES)})
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
        WHERE status IN ({','.join(str(s) for s in BLOCKED_STATUSES)})
        GROUP BY client
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
        SELECT CAST(timestamp/3600 AS INTEGER)*3600 as hour_ts,
               status, COUNT(*) as cnt
        FROM queries
        GROUP BY hour_ts, status
        ORDER BY hour_ts
    """)
    rows = cur.fetchall()
 
    timeline = defaultdict(lambda: {"allowed": 0, "blocked": 0})
    for r in rows:
        ts = r["hour_ts"]
        if r["status"] in BLOCKED_STATUSES:
            timeline[ts]["blocked"] += r["cnt"]
        else:
            timeline[ts]["allowed"] += r["cnt"]
 
    timeline_data = [
        {
            "timestamp": ts,
            "label": datetime.utcfromtimestamp(ts).strftime("%m/%d %H:%M"),
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
            "time": datetime.utcfromtimestamp(r["timestamp"]).strftime("%H:%M:%S"),
            "domain": r["domain"],
            "client": r["client"],
            "status": STATUS_LABELS.get(r["status"], f"Status {r['status']}"),
            "blocked": r["status"] in BLOCKED_STATUSES
        }
        for r in cur.fetchall()
    ]
 
    conn.close()
 
    return jsonify({
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
    })
 
@app.route("/api/alerts/stream")
def alert_stream():
    """SSE endpoint — dashboard connects here to receive real-time alerts."""
    def generate():
        my_queue = []
        with alert_lock:
            alert_subscribers.append(my_queue)
        try:
            yield "data: {\"type\": \"connected\"}\n\n"
            while True:
                if my_queue:
                    alert = my_queue.pop(0)
                    yield f"data: {json.dumps(alert)}\n\n"
                else:
                    yield ": heartbeat\n\n"
                time.sleep(1)
        except GeneratorExit:
            with alert_lock:
                if my_queue in alert_subscribers:
                    alert_subscribers.remove(my_queue)
 
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
 
@app.route("/api/action/allow", methods=["POST"])
def action_allow():
    """Whitelist a domain in Pi-hole."""
    data = request.json
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "no domain"}), 400
    try:
        result = subprocess.run(
            ["pihole", "allowlist", domain],
            capture_output=True, text=True, timeout=10
        )
        print(f"[allow] {domain}: {result.stdout.strip()}")
        return jsonify({"ok": True, "domain": domain, "output": result.stdout.strip()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
@app.route("/api/action/block", methods=["POST"])
def action_block():
    """Block client IP via iptables."""
    data = request.json
    client_ip = data.get("client", "").strip()
    if not client_ip:
        return jsonify({"error": "no client IP"}), 400
    try:
        result = subprocess.run(
            ["iptables", "-I", "FORWARD", "-s", client_ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10
        )
        print(f"[block] iptables DROP {client_ip}: {result.returncode}")
        return jsonify({"ok": True, "client": client_ip})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
@app.route("/api/action/unblock", methods=["POST"])
def action_unblock():
    """Remove iptables block for a client IP."""
    data = request.json
    client_ip = data.get("client", "").strip()
    if not client_ip:
        return jsonify({"error": "no client IP"}), 400
    try:
        result = subprocess.run(
            ["iptables", "-D", "FORWARD", "-s", client_ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10
        )
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