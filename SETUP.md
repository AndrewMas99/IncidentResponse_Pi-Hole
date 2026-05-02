# Setup Guide

## Prerequisites

* Raspberry Pi 4 running Raspberry Pi OS (64-bit recommended)
* Internet connection on the Pi
* A second device on the same network to use as a test client

---

## 1. System Update

```bash
sudo apt update && sudo apt upgrade -y
```

---

## 2. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
newgrp docker
sudo apt install docker-compose-plugin -y
```

Verify:

```bash
docker --version
docker compose version
```

---

## 3. Deploy Pi-hole via Docker

```bash
mkdir -p ~/pihole
cd ~/pihole
nano docker-compose.yml
```

Paste in the contents of `docker-compose.yml` from this repo, then start the container:

```bash
docker compose up -d
docker ps
```

Pi-hole should now be running. Confirm at `http://<pi-ip>/admin`.

---

## 4. Install Python Dependencies

```bash
pip3 install -r requirements.txt --break-system-packages
```

---

## 5. Deploy the Dashboard

Copy `App.py` and `index.html` to the Pi's home directory (e.g. via VS Code Remote SSH or `scp`), then run:

```bash
sudo python3 App.py
```

`sudo` is required for iptables access. Open `http://<pi-ip>:5000` in a browser on any device on the network.

---

## 6. Verify DNS Is Routing Through Pi-hole

On a client machine, manually set DNS to the Pi's IP address (`192.168.0.2`). Then run:

```bash
nslookup google.com 192.168.0.2
```

If you get a valid response, DNS is routing through Pi-hole and the dashboard should start showing that client's queries within a few seconds.

---

## 7. Auto-start with systemd (Recommended)

```bash
sudo nano /etc/systemd/system/pihole-dashboard.service
```

Paste:

```ini
[Unit]
Description=Pi-hole Dashboard
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/am1
ExecStart=/usr/bin/python3 /home/am1/App.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable pihole-dashboard
sudo systemctl start pihole-dashboard
sudo systemctl status pihole-dashboard
```

---

## 8. Useful Ongoing Commands

```bash
# Dashboard
sudo journalctl -u pihole-dashboard -f     # live logs
sudo systemctl restart pihole-dashboard    # restart after editing App.py
sudo systemctl stop pihole-dashboard       # stop

# Pi-hole container
docker compose restart                     # restart Pi-hole
docker logs pihole                         # Pi-hole container logs

# Verify iptables block rules are active
sudo iptables -L DOCKER-USER -n --line-numbers

# Check persisted blocked clients
cat ~/blocked_clients.json

# Flush DNS cache on Windows test client
ipconfig /flushdns
```

---

## 9. Find the Pi-hole Database (if needed)

```bash
docker inspect pihole
find / -name "pihole-FTL.db" 2>/dev/null
```

The database is typically mounted at `/etc/pihole/pihole-FTL.db` on the host.
