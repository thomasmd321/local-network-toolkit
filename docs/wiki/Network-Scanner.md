# Network Scanner (`network_scanner.py`)

For desktop/server environments (Linux, macOS, Windows, Termux on Android).
Prefers an ARP scan via [scapy](https://scapy.net/) — fast, and returns MAC
addresses directly — and falls back automatically to a multithreaded ping
sweep plus the system ARP table if scapy isn't installed or the process
doesn't have the privileges an ARP scan needs (typically root/administrator).

```
python network_scanner.py                             # auto-detect local subnet
python network_scanner.py 192.168.1.0/24               # scan a specific subnet
python network_scanner.py 192.168.1.0/24,10.0.0.0/24   # scan several subnets
python network_scanner.py --all-subnets                # every subnet this machine
                                                        # has a network interface on
python network_scanner.py --timeout 2
```

`--all-subnets` auto-detects and scans every local subnet across all of the
machine's network interfaces (e.g. Wi-Fi *and* Ethernet, or a VPN), instead
of just the one on the default route. Multiple subnets (whether from
`--all-subnets` or a comma-separated list) are scanned concurrently, not one
at a time, so having several VLANs doesn't multiply the wall-clock cost.

Both optional dependencies below are just that — optional; the script works
out of the box without either, falling back to slower/less detailed methods.
See [[Getting Started|Getting-Started]] for install commands.

## Hostnames and vendors, filled in automatically

- Any device still missing a hostname after ARP/reverse-DNS gets the same
  mDNS reverse lookup and DNS-SD Cast service discovery as [[Mobile Network
  Scanner|Mobile-Network-Scanner]] — and unlike on iOS, there's no sandboxing
  here to block it, so this reliably resolves things like Chromecast names
  on desktop/Termux.
- Any device with a MAC address gets it looked up against the IEEE's public
  OUI registry to identify the manufacturer (e.g. `aa:bb:cc:dd:ee:ff` →
  `Apple, Inc.`). The registry (a few MB) is downloaded once and cached at
  `~/.cache/network_scanner_oui.txt`; every run after that reuses the cache
  instantly, with no network call at all, until you ask otherwise.

```
python network_scanner.py --mdns-timeout 0.5
python network_scanner.py --no-vendor-lookup     # skip vendor lookup entirely
python network_scanner.py --refresh-vendor-db    # force a fresh OUI download
```

## IPv6 (`--ipv6`, Linux/macOS only)

Everything above is IPv4-only — ARP and ping-sweep both assume a scannable
subnet, which doesn't exist for IPv6 (a /64 has 2⁶⁴ addresses, versus 254
for an IPv4 /24). `--ipv6` instead sends a single ICMPv6 echo to the local
link's all-nodes multicast address (`ff02::1`) on every interface, then
reads back whatever answered from the OS's own IPv6 neighbor cache. Results
are appended below the IPv4 table, not numerically interleaved (comparing
an IPv4 and IPv6 address for sorting doesn't mean anything).

```
python network_scanner.py --ipv6
python network_scanner.py --ipv6 --ipv6-timeout 5
```

**Known limitations:** Windows isn't supported (the flag is safe to pass,
it'll just find nothing there); no hostname resolution for IPv6 devices
(`mdns_reverse_lookup()` builds an IPv4-style reverse name that doesn't
apply). MAC vendor lookup still works normally.

## Port scanning and risky-port flagging (on by default)

Every discovered device also gets probed for an open port from
`DEFAULT_PORTS` — the same port list `mobile_network_scanner.py` uses (`80,
443, 22, 445, 139, 8080, 8443, 62078, 3389, 5000, 7000`). Separately, every
device is checked against `RISKY_PORTS` — a small, non-exhaustive list of
ports worth a second look on a home network (telnet, FTP, SMB, RDP, VNC) —
*independent* of the general port probe, which stops at the first open port
and could otherwise miss telnet if port 80 happened to be checked first.

```
python network_scanner.py --no-scan-ports          # skip both entirely
python network_scanner.py --ports 22,80,443        # probe a custom list instead
python network_scanner.py --no-risky-ports          # keep the probe, skip the security check
python network_scanner.py --port-timeout 0.5
```

## Colorized output

NEW devices print in green, a device exposing a risky port prints in red
(taking priority if it's also NEW), and the missing-device report prints
dim. Plain ANSI codes, no dependency — auto-disabled when stdout isn't a
terminal or the [`NO_COLOR`](https://no-color.org) env var is set;
`--no-color` disables it explicitly.

## Single-device deep dive (`--identify IP`)

The bulk scan is tuned for speed across up to 254 hosts, so it can't afford
long timeouts or a wide port list. `--identify` investigates one host
thoroughly instead: many more ports (FTP, SMTP, MySQL, Redis, Plex,
printers — see `_IDENTIFY_PORTS`), a banner-grab attempt on each open one,
and the full hostname/vendor resolution chain with more generous timeouts.

```
python network_scanner.py --identify 192.168.1.26
```

Banner grabbing (`grab_banner()`) reads whatever a service reveals about
itself right after connecting — SSH sends its version string unprompted,
HTTP(S) servers reveal a lot in response to a bare `HEAD /`. For a port
outside the well-known HTTP set, it tries listening first and only sends an
HTTP probe if nothing arrived, since plenty of IoT admin UIs run HTTP on
non-standard ports. Not every service says anything at all: binary
protocols like SMB or RDP report no banner, the same as a closed port would.

**Hardened against a real DoS**: the mDNS `_decode_dns_name()` helper this
script uses for hostname resolution had no guard against a DNS
compression-pointer cycle until a repo-wide review caught and fixed it —
see [[mDNS Browser|mDNS-Browser]] for details (a genuine, reproduced
infinite loop, not a theoretical concern).

## See also

- [[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]]
- [[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]]
- [[Quiet Mode & Doctor|Quiet-Mode-and-Doctor]] — `--doctor` checks scapy/ping/arp availability up front
