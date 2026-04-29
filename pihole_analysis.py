#!/usr/bin/env python3
"""
Pi-hole Incident Response Analysis Script
Andrew Masone - Network Security Project

Connects to the Pi-hole FTL SQLite database and generates
analysis + visualizations for incident response reporting.
"""

import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
import os
import sys

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
DB_PATH = "/etc/pihole/pihole-FTL.db"   # adjust if needed
OUTPUT_DIR = "./pihole_report"

# Pi-hole status code meanings
STATUS_LABELS = {
    0:  "Unknown",
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
    11: "Allowed (Retried/Ignored)",
    12: "Blocked (Special Domain)",
    13: "Allowed (Gravity CNAME)",
    14: "Retried",
    15: "Allowed (DB busy)",
    16: "Cache Expired",
    17: "Cached (Stale)",
}

BLOCKED_STATUSES = {1, 5, 6, 7, 8, 9, 12}

# ─────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────
def load_data(db_path):
    print(f"[*] Connecting to database: {db_path}")
    if not os.path.exists(db_path):
        print(f"[!] Database not found at {db_path}")
        print("    Try: sudo cp /etc/pihole/pihole-FTL.db . && sudo chmod 644 pihole-FTL.db")
        print("    Then update DB_PATH in this script to './pihole-FTL.db'")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        "SELECT id, timestamp, type, status, domain, client, forward FROM queries",
        conn
    )
    conn.close()

    df["datetime"] = pd.to_datetime(df["timestamp"], unit="s")
    df["hour"] = df["datetime"].dt.floor("h")
    df["is_blocked"] = df["status"].isin(BLOCKED_STATUSES)
    df["status_label"] = df["status"].map(STATUS_LABELS).fillna("Other")

    print(f"[+] Loaded {len(df):,} queries spanning {df['datetime'].min()} → {df['datetime'].max()}")
    return df


# ─────────────────────────────────────────────
# ANALYSIS FUNCTIONS
# ─────────────────────────────────────────────
def print_summary(df):
    total = len(df)
    blocked = df["is_blocked"].sum()
    clients = df["client"].nunique()

    print("\n" + "="*55)
    print("  PI-HOLE INCIDENT RESPONSE SUMMARY")
    print("="*55)
    print(f"  Total Queries      : {total:,}")
    print(f"  Blocked Queries    : {blocked:,} ({blocked/total*100:.1f}%)")
    print(f"  Allowed Queries    : {total - blocked:,} ({(total-blocked)/total*100:.1f}%)")
    print(f"  Unique Clients     : {clients}")
    print(f"  Unique Domains     : {df['domain'].nunique():,}")
    print("="*55)

    print("\n[Status Breakdown]")
    status_counts = df.groupby("status_label").size().sort_values(ascending=False)
    for label, count in status_counts.items():
        print(f"  {label:<30} {count:>6,}")

    print("\n[Top 10 Blocked Domains]")
    blocked_df = df[df["is_blocked"]]
    top_blocked = blocked_df["domain"].value_counts().head(10)
    for domain, count in top_blocked.items():
        print(f"  {count:>5}  {domain}")

    print("\n[Top 10 Most Active Clients]")
    top_clients = df["client"].value_counts().head(10)
    for client, count in top_clients.items():
        blocked_by_client = df[(df["client"] == client) & df["is_blocked"]].shape[0]
        print(f"  {client:<20}  {count:>5} total  |  {blocked_by_client:>4} blocked")


# ─────────────────────────────────────────────
# VISUALIZATION
# ─────────────────────────────────────────────
def plot_all(df, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    plt.style.use("dark_background")
    ACCENT = "#00d4aa"
    RED    = "#ff4d6d"
    BLUE   = "#4fc3f7"
    GRAY   = "#888888"

    # ── 1. Query volume over time (allowed vs blocked) ──────────────
    fig, ax = plt.subplots(figsize=(14, 5))
    hourly = df.groupby(["hour", "is_blocked"]).size().unstack(fill_value=0)
    if True in hourly.columns:
        ax.fill_between(hourly.index, hourly[True], color=RED, alpha=0.7, label="Blocked")
    if False in hourly.columns:
        ax.fill_between(hourly.index, hourly[False], color=ACCENT, alpha=0.4, label="Allowed")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%m/%d %H:%M"))
    plt.xticks(rotation=30, ha="right")
    ax.set_title("Query Volume Over Time", fontsize=14, color="white", pad=12)
    ax.set_xlabel("Time")
    ax.set_ylabel("Queries per Hour")
    ax.legend()
    plt.tight_layout()
    fig.savefig(f"{output_dir}/1_query_volume_over_time.png", dpi=150)
    plt.close(fig)
    print("[+] Saved: 1_query_volume_over_time.png")

    # ── 2. Status breakdown pie chart ───────────────────────────────
    fig, ax = plt.subplots(figsize=(9, 7))
    status_counts = df["status_label"].value_counts()
    colors = [RED if "Blocked" in l else ACCENT if "Cache" in l else BLUE for l in status_counts.index]
    wedges, texts, autotexts = ax.pie(
        status_counts,
        labels=status_counts.index,
        autopct="%1.1f%%",
        colors=colors,
        startangle=140,
        textprops={"color": "white", "fontsize": 9}
    )
    ax.set_title("Query Status Distribution", fontsize=14, color="white", pad=12)
    plt.tight_layout()
    fig.savefig(f"{output_dir}/2_status_distribution.png", dpi=150)
    plt.close(fig)
    print("[+] Saved: 2_status_distribution.png")

    # ── 3. Top 15 blocked domains ────────────────────────────────────
    fig, ax = plt.subplots(figsize=(10, 7))
    top_blocked = df[df["is_blocked"]]["domain"].value_counts().head(15)
    bars = ax.barh(top_blocked.index[::-1], top_blocked.values[::-1], color=RED, alpha=0.85)
    ax.bar_label(bars, padding=4, color="white", fontsize=9)
    ax.set_title("Top 15 Blocked Domains", fontsize=14, color="white", pad=12)
    ax.set_xlabel("Block Count")
    ax.tick_params(axis="y", labelsize=9)
    plt.tight_layout()
    fig.savefig(f"{output_dir}/3_top_blocked_domains.png", dpi=150)
    plt.close(fig)
    print("[+] Saved: 3_top_blocked_domains.png")

    # ── 4. Top 10 most queried domains (all) ─────────────────────────
    fig, ax = plt.subplots(figsize=(10, 6))
    top_domains = df["domain"].value_counts().head(10)
    bars = ax.barh(top_domains.index[::-1], top_domains.values[::-1], color=BLUE, alpha=0.85)
    ax.bar_label(bars, padding=4, color="white", fontsize=9)
    ax.set_title("Top 10 Most Queried Domains (All Traffic)", fontsize=14, color="white", pad=12)
    ax.set_xlabel("Query Count")
    ax.tick_params(axis="y", labelsize=9)
    plt.tight_layout()
    fig.savefig(f"{output_dir}/4_top_queried_domains.png", dpi=150)
    plt.close(fig)
    print("[+] Saved: 4_top_queried_domains.png")

    # ── 5. Per-client activity: total vs blocked ──────────────────────
    fig, ax = plt.subplots(figsize=(10, 6))
    client_total   = df.groupby("client").size().sort_values(ascending=False).head(10)
    client_blocked = df[df["is_blocked"]].groupby("client").size().reindex(client_total.index, fill_value=0)
    x = range(len(client_total))
    ax.bar(x, client_total.values, color=BLUE, alpha=0.6, label="Total")
    ax.bar(x, client_blocked.values, color=RED, alpha=0.85, label="Blocked")
    ax.set_xticks(list(x))
    ax.set_xticklabels(client_total.index, rotation=30, ha="right", fontsize=9)
    ax.set_title("Top 10 Clients — Total vs Blocked Queries", fontsize=14, color="white", pad=12)
    ax.set_ylabel("Query Count")
    ax.legend()
    plt.tight_layout()
    fig.savefig(f"{output_dir}/5_client_activity.png", dpi=150)
    plt.close(fig)
    print("[+] Saved: 5_client_activity.png")

    # ── 6. Query frequency heatmap (hour of day × day of week) ───────
    if len(df["datetime"].dt.date.unique()) > 1:
        fig, ax = plt.subplots(figsize=(12, 5))
        df["dow"] = df["datetime"].dt.day_name()
        df["hod"] = df["datetime"].dt.hour
        pivot = df.groupby(["dow", "hod"]).size().unstack(fill_value=0)
        day_order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
        pivot = pivot.reindex([d for d in day_order if d in pivot.index])
        im = ax.imshow(pivot.values, aspect="auto", cmap="YlOrRd")
        ax.set_xticks(range(24))
        ax.set_xticklabels([f"{h:02d}:00" for h in range(24)], rotation=45, ha="right", fontsize=7)
        ax.set_yticks(range(len(pivot.index)))
        ax.set_yticklabels(pivot.index)
        plt.colorbar(im, ax=ax, label="Query Count")
        ax.set_title("Query Heatmap — Hour of Day × Day of Week", fontsize=14, color="white", pad=12)
        plt.tight_layout()
        fig.savefig(f"{output_dir}/6_query_heatmap.png", dpi=150)
        plt.close(fig)
        print("[+] Saved: 6_query_heatmap.png")
    else:
        print("[~] Skipped heatmap (need multiple days of data)")

    print(f"\n[✓] All charts saved to: {output_dir}/")


# ─────────────────────────────────────────────
# SUSPICIOUS ACTIVITY FLAGS
# ─────────────────────────────────────────────
def flag_suspicious(df):
    print("\n[!] SUSPICIOUS ACTIVITY FLAGS")
    print("="*55)

    # Clients with unusually high block rates (>30% of their traffic blocked)
    client_stats = df.groupby("client").agg(
        total=("id", "count"),
        blocked=("is_blocked", "sum")
    )
    client_stats["block_rate"] = client_stats["blocked"] / client_stats["total"]
    suspicious = client_stats[(client_stats["block_rate"] > 0.30) & (client_stats["total"] > 20)]

    if suspicious.empty:
        print("  No clients with >30% block rate (min 20 queries)")
    else:
        print("  Clients with high block rate (>30%):")
        for ip, row in suspicious.iterrows():
            print(f"    {ip:<20}  {row['blocked']}/{row['total']} blocked  ({row['block_rate']*100:.1f}%)")

    # Domains queried by many different clients (potential C2 beacon indicator)
    domain_clients = df.groupby("domain")["client"].nunique()
    widespread = domain_clients[domain_clients > 3].sort_values(ascending=False).head(10)
    print(f"\n  Domains queried by 3+ different clients (lateral spread indicator):")
    for domain, count in widespread.items():
        print(f"    {count} clients → {domain}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    df = load_data(DB_PATH)
    print_summary(df)
    flag_suspicious(df)
    plot_all(df, OUTPUT_DIR)
