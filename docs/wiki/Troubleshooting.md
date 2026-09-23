# Troubleshooting

## Start with `--doctor`

Before anything else, run `--doctor` on whichever scanner you're using —
it checks this environment's actual capabilities (scapy, `ping`/`arp`,
cache writability, mDNS multicast) up front instead of discovering a
limitation mid-scan as a blank column or a silently-skipped feature. See
[[Quiet Mode & Doctor|Quiet-Mode-and-Doctor]].

```
python network_scanner.py --doctor
python mobile_network_scanner.py --doctor
```

## iOS: mDNS/DNS-SD fails with "No route to host"

**Not a bug** — this is iOS's Local Network Privacy model. Apps must
declare, at the app-bundle level (`NSBonjourServices` in `Info.plist`),
exactly which Bonjour service types they intend to use. A generic terminal
app (a-Shell, Pythonista, Pyto) has no way to declare that for a script
typed at runtime, so iOS blocks the multicast traffic before it ever
leaves the device — regardless of the general "Local Network" permission
toggle. Confirm it's this, not something else, with [[mDNS
Diagnostic|mDNS-Diagnostic]]:

```
python mdns_diagnostic.py
```

**What still works on iOS:** plain TCP port scanning, banner grabbing, and
everything else that's ordinary unicast traffic — only multicast-based
mDNS/DNS-SD lookups are blocked. See [[Mobile Network
Scanner|Mobile-Network-Scanner]] for the full hostname-resolution fallback
chain that still functions.

## `network_scanner.py` finds no MAC addresses / falls back to ping sweep

Either `scapy` isn't installed, or the process doesn't have the
privileges an ARP scan needs (typically root/administrator). Run
`--doctor` to confirm which. The ping-sweep + system-ARP-table fallback
still works without either, just without MAC addresses (and so without
vendor lookup or IP-conflict alerts, both of which need a real MAC — see
[[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]]).

## Tools with an explicitly unverified-against-real-hardware limitation

This project is upfront about where its own development environment
couldn't exercise the real thing. Each of these works correctly against
everything the sandbox *could* simulate (mocked or hand-built real
protocol traffic), but hasn't been confirmed against the genuine
article — treat a first real run as the verification it hasn't had yet,
and see each tool's own wiki page for exactly what was and wasn't tested:

| Tool | What's unverified |
|---|---|
| [[ARP Monitor\|ARP-Monitor]] | Real ARP traffic on real hardware (broken scapy install, no raw-socket privileges in dev) |
| [[Wi-Fi Scanner\|Wifi-Scanner]] | Real `nmcli`/`airport`/`netsh` output on real Wi-Fi hardware |
| [[Traceroute Mapper\|Traceroute-Mapper]] | Real `traceroute`/`tracert` output (no such binary in dev) |
| [[UPnP Audit\|UPnP-Audit]] | A real router's UPnP stack (only a simulated gateway was available) |
| [[DHCP Monitor\|DHCP-Monitor]] | Real DHCP traffic from a physical network; the entire Windows port-68 bind path |
| [[Network Scanner\|Network-Scanner]] `--ipv6` | Not supported on Windows at all (by design, not just untested) |
| [[Windows ARP/DHCP Watch\|Windows-ARP-DHCP-Watch]] | The real `arp.exe`/`ipconfig.exe` output format on an actual Windows install (dev environment is Linux) |

## MQTT publish fails

A failed publish (unreachable broker, bad credentials, TLS handshake
failure) prints a warning to stderr and does **not** crash the scan — this
is deliberate. Check:
- The broker host/port and that `--mqtt-tls`/port 8883 match how the
  broker is actually configured.
- A self-signed broker certificate needs `--mqtt-insecure-tls` alongside
  `--mqtt-tls`, or the TLS handshake will fail certificate verification.
- Credentials resolve in this order: `--mqtt-password` → `--mqtt-password-file`
  → `$MQTT_PASSWORD`. See [[Notifications, Metrics &
  MQTT|Notifications-Metrics-and-MQTT]].

## Where to look next

- [[Getting Started|Getting-Started]] for installation and the optional
  `scapy`/`psutil` dependencies.
- [[Home]] for the full tool index.
