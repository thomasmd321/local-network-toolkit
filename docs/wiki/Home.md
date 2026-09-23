# Local Network Toolkit

Python tools for understanding your local network — no required third-party
dependencies, every tool works out of the box, and two of them ([[Network
Scanner|Network-Scanner]] and [[Mobile Network Scanner|Mobile-Network-Scanner]])
optionally get faster/richer with `scapy`/`psutil` installed.

| Question | Tool |
|---|---|
| Which devices are on my network? | [[Network Scanner\|Network-Scanner]] (desktop/server) or [[Mobile Network Scanner\|Mobile-Network-Scanner]] (sandboxed Python, e.g. iOS) |
| What changed between two saved scans? | [[Scan Diff\|Scan-Diff]] |
| What services are being advertised (printers, AirPlay, HomeKit, ...)? | [[mDNS Browser\|mDNS-Browser]] |
| Is mDNS even working from this device? | [[mDNS Diagnostic\|mDNS-Diagnostic]] |
| What Wi-Fi networks are in range, and is one of them a rogue twin? | [[Wi-Fi Scanner\|Wifi-Scanner]] |
| Is a risky port reachable from the whole internet, not just my LAN? | [[Exposure Check\|Exposure-Check]] |
| Where along the path is a slow connection actually slow? | [[Traceroute Mapper\|Traceroute-Mapper]] |
| Is something spoofing another device's IP right now? | [[ARP Monitor\|ARP-Monitor]] |
| Is an unauthorized DHCP server handing out its own leases? | [[DHCP Monitor\|DHCP-Monitor]] |
| Is my DNS being hijacked? | [[DNS Check\|DNS-Check]] |
| How fast is the LAN itself, not my internet connection? | [[LAN Throughput\|LAN-Throughput]] |
| Which ports has my router's UPnP quietly opened to the internet? | [[UPnP Audit\|UPnP-Audit]] |
| Who's home right now, glanceable from a phone browser? | [[Network Dashboard\|Network-Dashboard]] |
| Same ARP/DHCP watching, but on Windows with no admin rights? | [[Windows ARP/DHCP Watch\|Windows-ARP-DHCP-Watch]] |

New to this repo? Start with [[Getting Started|Getting-Started]].

## The two scanners

[[Network Scanner|Network-Scanner]] (`network_scanner.py`) is for desktop/
server environments (Linux, macOS, Windows, Termux on Android): ARP scan via
`scapy` when available, falling back to a ping sweep + the system ARP table.
[[Mobile Network Scanner|Mobile-Network-Scanner]] (`mobile_network_scanner.py`)
is for sandboxed Python runtimes that can't spawn subprocesses or open raw
sockets — most notably iOS apps like a-Shell — and discovers hosts with
plain TCP connects instead.

Both scanners share a large set of features, each documented on its own page
since they apply (almost) identically to both scripts:

- [[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]] — NEW/CHG markers, `--watch`, `--diff-only`, `--retries`, IP-conflict alerts
- [[Labels & Registry Backup|Labels-and-Registry-Backup]] — `--set-label`, `--export-known-devices`/`--import-known-devices`
- [[Exporting Results & History|Exporting-Results-and-History]] — `--output`, `--log-history`, and [[Scan Diff|Scan-Diff]]
- [[Config Profiles|Config-Profiles]] — `--profile`, saved flag combinations
- [[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]] — `--notify-webhook`, `--metrics-file` (Prometheus), `--mqtt-host` (Home Assistant presence)
- [[Quiet Mode & Doctor|Quiet-Mode-and-Doctor]] — `--quiet`, `--doctor`

## Everything else

13 standalone scripts each answer one question the scanners don't — see
the table above, or the sidebar. Every tool prints a plain results table
to the terminal and most support `--output FILE` to save results as JSON
or CSV.

## Design philosophy (why no third-party dependency is ever required)

Every wire protocol these tools speak — DHCP, DNS, mDNS/DNS-SD, SSDP/UPnP,
MQTT — is implemented from scratch against its RFC/spec using only the
Python standard library (`socket`, `struct`, `ssl`), rather than adding a
dependency for it. `scapy` and `psutil` are the two exceptions, and both are
strictly optional: [[Network Scanner|Network-Scanner]] and [[ARP
Monitor|ARP-Monitor]] fall back to slower methods without `scapy`, and
`--all-subnets` without `psutil` just isn't offered. Each script is also
self-contained: shared logic (mDNS wire format, colorized output, risky-port
lists) is duplicated across files rather than factored into a shared
library, so any single script can be copied out and run on its own — see
[[Getting Started|Getting-Started]] for exactly this, running
`mobile_network_scanner.py` alone on an iPhone.

## Full PDF guide

📄 [`docs/network_scanner_guide.pdf`](https://github.com/thomasmd321/local-network-toolkit/blob/main/docs/network_scanner_guide.pdf)
is a printable setup/usage guide with pipeline diagrams and a full options
reference for the two scanner scripts, generated from
[`docs/pdf_guide/generate_guide.py`](https://github.com/thomasmd321/local-network-toolkit/blob/main/docs/pdf_guide/generate_guide.py).
This wiki is the more detailed, more frequently updated reference; the PDF
is a snapshot for printing/offline reading.
