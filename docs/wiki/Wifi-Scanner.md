# Wi-Fi Scanner (`wifi_scanner.py`)

A different, complementary question from the other tools here: not "what
devices are on my network," but "what networks are in radio range at
all," including ones you're not connected to. A network that feels slow
is often channel congestion from a neighbor on the same channel, or a weak
signal — neither of which device discovery can see.

```
python wifi_scanner.py
python wifi_scanner.py --timeout 15
python wifi_scanner.py --output networks.json
```

Shells out to each OS's own Wi-Fi tooling rather than a raw 802.11 library
(none ships in the standard library, and a packet-capture-based scanner
would need monitor mode and root/administrator everywhere): `nmcli` on
Linux, the `airport` command-line tool on macOS (still present despite
Apple's deprecation notice), and `netsh wlan show networks` on Windows.
Signal strength is kept in whatever unit each platform's own tool reports
(a percentage on Linux/Windows, dBm on macOS) rather than converted
between them — there's no one true conversion, so labeling each honestly
beats a false unification. An open/unencrypted network is called out in
the output as a security nod, the same spirit as `RISKY_PORTS` elsewhere
in this project.

## Evil-twin / rogue-AP detection

Each scan is compared against a small local registry of previously seen
networks (`~/.cache/wifi_scanner_known_networks.json`) to catch two
patterns:

- **A downgrade attack**: a familiar SSID suddenly answering with *weaker*
  security than it's ever shown before — a legitimate AP doesn't just drop
  encryption on its own.
- **A new access point**: a familiar SSID answering from a BSSID never
  seen before — softer signal, since it could be a genuinely new/roaming
  AP on a mesh network, so it's flagged for a second look, not treated as
  proof.

```
python wifi_scanner.py --no-evil-twin-check
python wifi_scanner.py --forget-known-networks
```

The registry keys purely by SSID (not by location), so a downgrade
reported from a **brand-new BSSID** gets softer wording than one from a
BSSID already known under that SSID — a repo-wide review caught that the
combination of "weaker security" and "never-seen BSSID" is also exactly
what scanning an unrelated network that happens to reuse a common SSID
(a hotel or coffee-shop name, a default router SSID) looks like, so that
case's message now says it could be either, rather than asserting a
"classic evil-twin/downgrade pattern" with no hedge.

## Known limitation, stated plainly

The parsing for all three platforms is verified only against mocked
command output matching each tool's documented format, not against real
Wi-Fi hardware on any of the three OSes — the environment this was built
in has none of `nmcli`/`airport`/`netsh` and no wireless hardware at all.
Treat a first real run on any platform as the verification it hasn't had
yet. The evil-twin logic itself needs no hardware to verify, and was run
for real end to end against a fake `nmcli` script on `PATH`.

## See also

- [[Troubleshooting]]
