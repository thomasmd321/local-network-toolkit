# Network Dashboard (`network_dashboard.py`)

Every scanner here prints to a terminal and moves on — if one is left
running under `--watch` on an always-on machine, "is anyone home right
now" otherwise means SSHing back in and reading scrollback. This instead
serves whatever `--watch` has already persisted to its known-devices
registry as a small HTML page, glanceable from a phone's browser on the
same network.

```
python network_dashboard.py                                  # loopback-only, network_scanner.py's registry
python network_dashboard.py --bind 0.0.0.0 --token my-secret  # reachable from your phone, minimally gated
python network_dashboard.py --registry ~/.cache/mobile_network_scanner_known_devices.json
```

A pure *reader*: it never triggers a scan itself, and needs nothing beyond
a JSON file and stdlib's `http.server` — no scapy, no subprocess, no raw
sockets, so unlike almost everything else here, this specific script's own
operation is fully iOS-sandbox-compatible (though what's usually worth
pointing it at — a desktop's `--watch` registry — typically isn't).
Auto-refreshes via a plain `<meta>` tag, no JavaScript at all.

## Security, stated plainly

Your device inventory (IPs, hostnames, vendor strings, MACs) isn't public
information, and this page has no transport encryption and no
authentication by default. It defaults to `--bind 127.0.0.1` (reachable
only from this machine) for exactly that reason — reaching it from a
phone means explicitly choosing `--bind 0.0.0.0` (or a LAN address), which
then serves that inventory, unencrypted, to anyone who can reach the port.
`--token` adds a minimal shared-secret query check for that case, but it's
still plain HTTP — **an SSH tunnel back to `--bind 127.0.0.1` is the
actually-secure way to reach this from elsewhere.** Every value pulled
from the registry is HTML-escaped before rendering, since a hostile device
could otherwise set a malicious hostname designed to inject markup into a
page you load from your phone.

## Verification

Fully verified for real: `render_dashboard_html()` is pure and
unit-tested, and the actual HTTP server (a real `ThreadingHTTPServer`, hit
with a real `urllib` GET over real loopback TCP) is exercised end to end
for both the plain and `--token`-gated paths — nothing here needs
privileges, hardware, or a real network to verify.

## See also

- [[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]]
- [[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]] — alternative ways to surface `--watch`'s findings
