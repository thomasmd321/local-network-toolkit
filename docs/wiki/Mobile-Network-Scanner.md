# Mobile Network Scanner (`mobile_network_scanner.py`)

For sandboxed Python runtimes that can't spawn subprocesses or open raw
sockets — most notably iOS apps like
[a-Shell](https://apps.apple.com/us/app/a-shell/id1473805438), Pythonista, or
Pyto. Instead of `ping`/`arp`/scapy, it discovers hosts by attempting plain
TCP connections to a handful of commonly-open ports (80, 443, 22, 445, 3389,
etc. — see `DEFAULT_PORTS` in the script), which only needs an ordinary
client socket.

```
python mobile_network_scanner.py                             # auto-detect local subnet
python mobile_network_scanner.py 192.168.1.0/24               # scan a specific subnet
python mobile_network_scanner.py 192.168.1.0/24,10.0.0.0/24   # scan several subnets
python mobile_network_scanner.py --timeout 0.5 --ports 22,80,443
```

This is best-effort: it won't find a device with none of the probed ports
open, so widen `--ports` if you're missing something you expect to see.
Unlike [[Network Scanner|Network-Scanner]], it can't auto-detect *every*
subnet a device is on — the iOS sandbox doesn't expose interface
enumeration — but you can pass multiple subnets yourself as a
comma-separated list if you know them.

Results show which port answered as a hint at what the device is (e.g.
`8009` = Chromecast, `554` = an RTSP camera, `1900`/`5353` = a UPnP/mDNS
smart-home device) — see `PORT_SERVICES` in the script for the full list.
A device with no hostname and an unfamiliar port is worth cross-checking
against your router's admin page (usually `192.168.1.1` in a browser).

## Banner grabbing

Each device's Banner column comes from `grab_banner()`, which reads
whatever the open port sends back: an HTTP `Server:` header, or a protocol
banner volunteered outright (SSH, FTP, etc.). This needs nothing beyond the
same plain `socket`/`ssl` primitives the rest of the script already uses,
so it works on iOS with no platform restrictions — often enough on its own
to identify a device with no hostname.

```
python mobile_network_scanner.py --no-banners   # skip for a faster scan
```

## Risky-port flagging

Every live device is independently checked against `RISKY_PORTS` — telnet,
FTP, SMB, RDP, VNC — regardless of which port the general probe matched
first. A device exposing one is flagged in a summary section, along with
why each port is considered risky. This is a hygiene check, not a security
audit.

```
python mobile_network_scanner.py --no-risky-ports
```

## Colorized output

Green for a NEW device, red for one exposing a risky port (red wins if
both apply, though the NEW marker text is still visible either way). Plain
ANSI codes; auto-disables when stdout isn't a terminal, and also respects
`--no-color`/`NO_COLOR`.

## Hostname resolution, in order

1. **DNS-SD Cast service discovery** — for anything answering on the
   Chromecast control port (8009). Chromecasts generally *don't* answer
   reverse mDNS lookups (step 3) since Google's Cast stack skips that
   optional part of the spec — but they always answer "who offers
   `_googlecast._tcp.local`?", the actual mechanism the Google Home app
   uses to find them. This gets you the real device name.
2. **Reverse DNS** (`socket.gethostbyaddr`) — works for whatever your
   router/DHCP server names in its own DNS.
3. **mDNS/Bonjour reverse lookup** — for devices (printers, NAS boxes,
   smart speakers) that implement the optional reverse-PTR part of mDNS
   but never register real reverse DNS.

```
python mobile_network_scanner.py --mdns-timeout 0.5
```

This is a *best-effort* implementation, not a full mDNS/DNS-SD stack — one
query per method, reading whatever comes back within the timeout. Won't
work through mDNS reflectors/VLANs that don't forward multicast traffic.

## Known limitation on iOS

In testing, every mDNS/DNS-SD query from a-Shell failed outright with
`OSError(65, 'No route to host')` on the send itself — confirmed with
[[mDNS Diagnostic|mDNS-Diagnostic]] — which points to iOS's Local Network
Privacy model rather than a bug here: apps must declare, at the app-bundle
level (`NSBonjourServices` in `Info.plist`), exactly which Bonjour service
types they intend to use. A generic terminal app has no way to declare that
for a script typed at runtime, so iOS blocks the multicast traffic before
it ever leaves the device — regardless of the general "Local Network"
permission toggle, and regardless of anything this script does
differently. **Plain TCP port scanning is unaffected**, since that's
ordinary unicast traffic. If you hit this, your router's admin page or a
native network-scanner app (which declares the right entitlements at build
time) are the practical alternatives.

```
python mdns_diagnostic.py
```

See [[mDNS Diagnostic|mDNS-Diagnostic]] for what this standalone script
checks.

## Running on iPhone

See [[Getting Started|Getting-Started]] for the a-Shell install/curl steps.

## See also

- [[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]]
- [[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]]
