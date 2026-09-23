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

## See also

- [[Troubleshooting]]
- [[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]]
