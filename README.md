
# Pi-hole as a Network-Level Incident Response Tool

### Live Dashboard with Real-Time DNS Monitoring and Client Enforcement

> 📸 **[HERO SCREENSHOT — Full dashboard in browser, all panels visible with live data populated. Ideally taken during active network traffic so numbers are real and the recent queries feed is full. Landscape crop, as wide as possible.]**

---

## 1. Project Overview

This project demonstrates how Pi-hole, a network-wide DNS sinkhole, can be used as a lightweight incident response tool to detect and contain suspicious network activity. Pi-hole runs inside a Docker container on a dedicated Raspberry Pi and is configured as the DNS resolver for all devices on the local network. Every DNS query made by every device is visible, logged, and subject to enforcement in real time.

The core deliverable is a custom Flask-based web dashboard (`App.py` + `index.html`) that connects directly to Pi-hole's SQLite database and live log file to provide a genuinely real-time view of network DNS activity — with no external dependencies, no third-party dashboards, and no polling delay. The dashboard includes watchlist-based alerting, per-client traffic enforcement via iptables, and a domain allowlist manager, all accessible from a browser on the local network.

---

## 2. Project Relevance

### Why Pi-hole Matters in Incident Response

Most security incidents do not start with a loud alarm. They start quietly — a device reaching out to a domain it should not be contacting. DNS is one of the most fundamental and most abused protocols in networking. Malware uses DNS to phone home to command-and-control (C2) servers. Phishing campaigns rely on DNS to redirect users. Data exfiltration can be tunneled through DNS. DNS-level visibility is therefore a foundational component of network security monitoring.

This project takes that principle and builds a practical, self-hosted tool on top of it. By sitting directly on the Raspberry Pi running Pi-hole and reading the same SQLite database and log file that Pi-hole itself uses, the dashboard achieves sub-second update latency without requiring Kafka, a message broker, or any cloud infrastructure.

The dashboard directly supports two phases of the NIST SP 800-61 Incident Response lifecycle:

* **Detection and Analysis:** The query feed updates in real time as DNS traffic occurs. Watchlist hits fire instant toast notifications with action buttons. Per-client block rate and query volume are surfaced immediately.
* **Containment:** From the dashboard, an operator can block a client IP via iptables or add a domain to Pi-hole's allowlist without touching the command line — in one click, during an active incident.

---

## 3. System Architecture

### Physical Setup

```
All Network Devices
        │
        │  DNS queries (routed via DHCP)
        ▼
  Raspberry Pi 4
  ├── Docker: Pi-hole container
  │     ├── DNS resolver (port 53)
  │     ├── pihole-FTL.db  (SQLite — all query history)
  │     └── /var/log/pihole/pihole.log  (live log, tailed in real time)
  │
  └── Python: Flask app (port 5000)
        ├── Watcher thread (tails pihole.log)
        ├── SSE: /api/stats/stream  → pushes stats on every new query
        ├── SSE: /api/alerts/stream → pushes watchlist hits instantly
        └── REST: block / unblock / allowlist / watchlist APIs
```

### How Live Updates Work

The Flask app runs a background watcher thread that tails `/var/log/pihole/pihole.log` in real time — the same way `tail -f` works. Every time a new DNS query line appears:

1. The domain is checked against the watchlist. If it matches, an alert is pushed immediately to all connected browsers via Server-Sent Events (SSE).
2. A debounce timer (1 second) determines whether to re-query the SQLite database and push a full stats update. This prevents hammering the database on high-traffic networks while still keeping the dashboard visibly live.

The browser connects to two persistent SSE streams on load and never polls. Updates arrive as they happen.

```
pihole.log (new line)
        │
        ├── Watchlist match? ──► push alert to /api/alerts/stream ──► toast notification
        │
        └── Debounce (1s) ──► query pihole-FTL.db ──► push to /api/stats/stream ──► dashboard re-renders
```

---

## 4. Tools and Stack

| Component           | Tool                           | Purpose                                                 |
| ------------------- | ------------------------------ | ------------------------------------------------------- |
| DNS Sinkhole        | Pi-hole (Docker)               | DNS resolver, blocklist enforcement, query logging      |
| Container Runtime   | Docker                         | Isolates Pi-hole on the Raspberry Pi                    |
| Backend             | Python 3 / Flask               | Serves dashboard, reads DB and log, manages SSE streams |
| Database            | SQLite (`pihole-FTL.db`)     | All historical DNS query data                           |
| Live Log            | `/var/log/pihole/pihole.log` | Real-time DNS event source                              |
| Frontend            | Vanilla HTML/CSS/JS + Chart.js | Dashboard UI, no framework dependencies                 |
| Network Enforcement | iptables                       | Client IP blocking via `FORWARD`chain DROP rules      |
| DNS Allowlisting    | `pihole allowlist`CLI        | Domain allowlisting via subprocess call                 |
| Remote Dev          | VS Code Remote SSH             | Development directly on the Raspberry Pi                |

> 📸 **[VS CODE SCREENSHOT — VS Code with the Remote SSH connection open to the Pi (the green "SSH: 192.168.0.2" bar visible in the bottom-left corner), with App.py or index.html open in the editor. This is exactly what you uploaded earlier — that screenshot is perfect for this spot.]**

---

## 5. Dashboard Features

### Real-Time Stats (event-driven, not polled)

* Total queries, blocked count, allowed count, block rate
* Unique clients and unique domains seen
* Block rate color-coded: green (normal), yellow (elevated >15%), red (high >30%)
* "Updated" timestamp reflects the moment of the last push from the server

> 📸 **[SCREENSHOT — Stat cards row at the top of the dashboard. Best taken when block rate is elevated so the red color-coding is visible. Crop tightly to just the five cards.]**

### Query Volume Timeline

* Hourly chart of allowed vs. blocked queries
* Rendered with Chart.js, updates in-place without flicker on each push

### Status Distribution

* Doughnut chart breaking down query outcomes by Pi-hole status code
* Color-coded: blocked (red), cached (blue), allowed (green)

> 📸 **[SCREENSHOT — The two chart panels side by side: the timeline on the left showing a visible spike in blocked traffic, and the doughnut chart on the right. If you can generate a spike by querying blocked domains repeatedly with nslookup right before screenshotting, the timeline will look much more interesting.]**

### Client Activity Table

* Per-device breakdown: total, allowed, blocked, block percentage with mini bar
* **Block** button: immediately adds an iptables `FORWARD DROP` rule for that IP
* **Unblock** button: removes the iptables rule
* Blocked clients marked with a red indicator that persists across re-renders

> 📸 **[SCREENSHOT — Client activity table with at least 2-3 devices visible. Ideally one client has been blocked so the red ● indicator and UNBLOCK button are visible in the same shot. This demonstrates the containment capability clearly.]**

### Top Blocked / Top Allowed Domains

* Animated bar lists showing the 10 most blocked and 10 most queried allowed domains
* Bar widths update smoothly on each stats push

### Recent Queries Feed

* Last 50 DNS queries with timestamp, domain, client IP, and status badge
* Blocked rows highlighted in red
* New queries flash green on arrival so activity is visible at a glance

> 📸 **[SCREENSHOT — Recent queries feed scrolled to the top, showing a mix of red-highlighted blocked rows and normal allowed rows. The contrast between the red blocked entries and the rest makes the feed look great and tells the story immediately.]**

### Watchlist Manager

* Editable list of domains to monitor (e.g. `tiktok.com`, `chatgpt.com`)
* Add or remove entries from the browser; changes take effect immediately in the watcher thread
* Watchlist persists in memory for the session

### Real-Time Alert Toasts

* When any device queries a watchlisted domain, a toast notification fires instantly
* Toast shows: domain, client IP, timestamp, whether it was blocked or allowed through
* One-click actions from the toast: **Allow Domain** (adds to Pi-hole allowlist) or **Block Client** (iptables DROP)
* Alerts auto-dismiss after 30 seconds; logged to the Alert Log panel

> 📸 **[SCREENSHOT — This is the money shot. Trigger it by running `nslookup chatgpt.com [your-pi-ip]` or `nslookup tiktok.com [your-pi-ip]` from another device or terminal while the dashboard is open. The red toast notification will pop up in the top-right corner. Capture it before it dismisses. Shows the real-time alerting working end-to-end.]**

### Alert Log

* Persistent in-session log of all watchlist hits
* Shows action taken (BLOCKED / ALLOWED / pending) color-coded per outcome

---

## 6. Running the Dashboard

### Prerequisites

bash

```bash
# On the Raspberry Pi, inside the Pi-hole working directory
pip3 install flask --break-system-packages
```

### Start

bash

```bash
sudo python3 App.py
```

`sudo` is required for iptables access. The watcher thread starts automatically and begins tailing the Pi-hole log.

> 📸 **[TERMINAL SCREENSHOT — The VS Code integrated terminal (or SSH session) showing the app starting up: the `[*] Watcher watching: /var/log/pihole/pihole.log` line, and ideally a few `[!] WATCHLIST HIT` lines below it from triggered alerts. Shows the backend working.]**

### Access

Open a browser on any device on the network:

```
http://192.168.0.2:5000
```

---

## 7. API Reference

| Method | Endpoint                  | Description                                      |
| ------ | ------------------------- | ------------------------------------------------ |
| GET    | `/api/stats`            | One-shot full stats snapshot (JSON)              |
| GET    | `/api/stats/stream`     | SSE stream — pushes stats on each new DNS query |
| GET    | `/api/alerts/stream`    | SSE stream — pushes watchlist hits instantly    |
| POST   | `/api/action/allow`     | Add domain to Pi-hole allowlist                  |
| POST   | `/api/action/block`     | Block client IP via iptables                     |
| POST   | `/api/action/unblock`   | Remove iptables block for client IP              |
| POST   | `/api/watchlist/add`    | Add domain to watchlist                          |
| POST   | `/api/watchlist/remove` | Remove domain from watchlist                     |

---

## 8. Key Design Decisions

**Event-driven over polling.** The watcher thread drives all updates. The browser never polls — it holds open two SSE connections and reacts to pushes. This eliminates the artificial delay of an interval timer and makes the dashboard feel genuinely live.

**Debouncing the DB reads.** The SQLite database is read at most once per second regardless of query volume. On a quiet network this means near-instant updates; on a busy network it prevents excessive load on the Pi without any visible lag to the user.

**`stream_with_context` for SSE.** Flask's default response buffering delays SSE delivery. Wrapping generators in `stream_with_context` ensures each event is flushed to the client immediately rather than accumulating in a buffer.

**No frontend framework.** The dashboard is a single `index.html` file with no build step, no npm, no bundler. Chart.js is loaded from a CDN. This keeps deployment as simple as copying two files to the Pi.

**iptables for containment.** Blocking a client at the iptables `FORWARD` chain level drops all traffic from that IP at the network layer — not just DNS. This is a meaningful containment action, not just a DNS block.

---

## 9. Limitations and Future Work

**Encrypted DNS (DoH/DoT).** Devices or apps configured to use DNS-over-HTTPS bypass Pi-hole entirely and will not appear in the dashboard. This is a real gap in any DNS-based monitoring approach.

**Blocklist freshness.** Pi-hole only blocks what is on its lists. Newly registered domains or C2 servers not yet in any blocklist will pass through. Behavioral detection (the watchlist and per-client volume analysis) partially compensates for this.

**Session-only state.** Blocked client IPs and watchlist additions are lost when the Flask app restarts. Persisting these to a config file or small database would be a straightforward improvement.

**iptables vs. nftables.** Newer Linux kernels on Raspberry Pi OS use nftables as the backend. The iptables commands used here work via the compatibility layer but a future version should call nftables directly.

**Potential extensions:**

* Persistent watchlist and blocked-client storage (JSON or SQLite)
* Email or webhook alerts for watchlist hits
* Per-client query history drill-down view
* Automatic blocklist updates from threat intelligence feeds
* Log forwarding to a SIEM (Splunk, ELK) for long-term retention

---

## 10. Resources

* Pi-hole Documentation: [https://docs.pi-hole.net/](https://docs.pi-hole.net/)
* Pi-hole Docker Setup: [https://github.com/pi-hole/docker-pi-hole](https://github.com/pi-hole/docker-pi-hole)
* Flask Documentation: [https://flask.palletsprojects.com/](https://flask.palletsprojects.com/)
* Server-Sent Events (MDN): [https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)
* Chart.js Documentation: [https://www.chartjs.org/docs/](https://www.chartjs.org/docs/)
* iptables man page: [https://linux.die.net/man/8/iptables](https://linux.die.net/man/8/iptables)
* NIST SP 800-61 (Incident Handling Guide): [https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
* DNS Sinkholes Explained: [https://www.sans.org/white-papers/33523/](https://www.sans.org/white-papers/33523/)
