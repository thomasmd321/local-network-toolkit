# Quiet Mode & Doctor

Applies to both [[Network Scanner|Network-Scanner]] and [[Mobile Network
Scanner|Mobile-Network-Scanner]].

## `--quiet`

Suppresses everything — even the scan's own "Scanning..." line — for a run
with nothing to report: no NEW devices, no port changes, no missing
devices, and no risky ports. As soon as one of those is true, the full
report prints exactly as it would without `--quiet`. This is meant for
`--watch` under cron/systemd, where a boring rescan producing zero output
(rather than a full table every time) is what makes "did anything happen"
easy to grep for or alert on — the same trigger condition
`--notify-webhook` uses (see [[Notifications, Metrics &
MQTT|Notifications-Metrics-and-MQTT]]), so the two pair naturally.

```
python network_scanner.py --watch 300 --quiet
python mobile_network_scanner.py --watch 300 --quiet
```

## `--doctor`

Skips the network scan and instead checks this environment for everything
the script can use — scapy, `ping`/`arp`, cache-directory writability,
mDNS multicast, and so on — reporting each with a clear pass/fail and, for
most, a note on the fallback that kicks in when it fails. It exits 0 if
every check passed, 1 otherwise, so it's usable as a pre-flight check in a
script.

```
python network_scanner.py --doctor
python mobile_network_scanner.py --doctor
```

A failed check here doesn't necessarily mean a scan will fail — most have
a documented fallback (no `arp` on PATH just means no MAC from that path,
not a crash) — it's diagnostic, not a hard prerequisite. The one exception
worth knowing: a failed mDNS check on `mobile_network_scanner.py` almost
always means iOS's Local Network Privacy restriction (see [[Mobile
Network Scanner|Mobile-Network-Scanner]] and [[mDNS
Diagnostic|mDNS-Diagnostic]]), which no retry or code change here can fix.

## Running `--watch` unattended as a systemd service

`--watch SECONDS` already loops on its own, so the natural way to run it
unattended on an always-on Linux machine is a persistent service (not a
timer — timers are for something systemd itself invokes periodically,
which `--watch` doesn't need). Pair it with `--quiet` above and whichever
of `--metrics-file`/`--mqtt-host`/`--notify-webhook` you're using (see
[[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]]), so the
service produces no routine log noise and only reports through those
channels:

```ini
# /etc/systemd/system/network-scanner-watch.service
[Unit]
Description=Local Network Toolkit - continuous scan (network_scanner.py --watch)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/local-network-toolkit
ExecStart=/usr/bin/python3 /path/to/local-network-toolkit/network_scanner.py 192.168.1.0/24 --watch 300 --quiet --metrics-file /var/lib/node_exporter/textfile_collector/network_scanner.prom --mqtt-host localhost --mqtt-password-file /etc/local-network-toolkit/mqtt_password
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```
sudo systemctl daemon-reload
sudo systemctl enable --now network-scanner-watch.service
journalctl -u network-scanner-watch.service -f
```

Runs as an ordinary user, not root — an ARP scan needs root (or scapy's
`CAP_NET_RAW`), which a plain user-level unit doesn't have, so it
transparently takes the ping-sweep + system ARP table fallback described
above (the same one `--doctor` reports on) instead of failing. Add
`AmbientCapabilities=CAP_NET_RAW` to `[Service]` if you specifically want
the faster ARP-based scan without running the whole unit as root —
standard systemd practice for this, though not something this project's
own test suite can verify end to end, since that needs a real systemd and
real raw-socket privileges neither CI nor this sandboxed dev environment
has.

[[Network Dashboard|Network-Dashboard]] is a second, independent
long-running process — nothing above starts it for you — so it wants its
own unit alongside it if you're serving the dashboard from the same
always-on machine:

```ini
# /etc/systemd/system/network-dashboard.service
[Unit]
Description=Local Network Toolkit - live dashboard
After=network-scanner-watch.service

[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/local-network-toolkit
ExecStart=/usr/bin/python3 /path/to/local-network-toolkit/network_dashboard.py --bind 127.0.0.1 --port 8765
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Leave `--bind` at its default `127.0.0.1` here unless you've deliberately
read [[Network Dashboard|Network-Dashboard]]'s security notice about
`--bind 0.0.0.0`.

## See also

- [[Troubleshooting]]
- [[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]]
- [[Network Dashboard|Network-Dashboard]]
