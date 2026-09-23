# Known-Device Tracking & Watch Mode

Applies to both [[Network Scanner|Network-Scanner]] and [[Mobile Network
Scanner|Mobile-Network-Scanner]].

## The registry, NEW, and missing devices

Both scripts persist a small local registry of every device they've ever
seen (`~/.cache/network_scanner_known_devices.json` and
`~/.cache/mobile_network_scanner_known_devices.json` respectively) and flag
anything not in it with a leading `NEW` marker in the results table.
`network_scanner.py` keys a device by its MAC address when it has one
(falling back to IP otherwise); `mobile_network_scanner.py` has no MAC to
work with at all, so it always keys by IP — meaning a DHCP lease change
there will make an existing device look "new" again.

The registry also powers the inverse report: any previously-seen device
that *didn't* show up in this scan (asleep, unplugged, out of Wi-Fi range)
is listed separately below the table. The registry itself is never pruned
— a device just stops appearing in that list again once a later scan finds
it.

```
python network_scanner.py                        # NEW markers on by default
python network_scanner.py --no-track-devices      # skip tracking entirely
python network_scanner.py --forget-known-devices  # reset the registry, marking
                                                   # everything NEW this run
```

## CHG: a changed port

Since the registry already stores each device's port from the last scan,
comparing that against this scan's port catches a device that's started
(or stopped) answering on a different port than usual — flagged in a
summary section, e.g. "1 device(s) with a changed port since last seen."
This is distinct from the risky-ports check: it doesn't care whether the
port is on `RISKY_PORTS`, only that it's *different* from normal. `NEW`
and `CHG` are mutually exclusive by definition.

## Watch mode

```
python network_scanner.py --watch 300           # rescan every 5 minutes
python mobile_network_scanner.py --watch 300
```

Turns either script into a lightweight "alert me when something joins my
network" monitor you leave running in a terminal (Ctrl+C to stop). The very
first run (or right after `--forget-known-devices`) marks every device
`NEW`, since nothing has been seen before yet — expected, not a bug.

## Only printing what changed (`--diff-only`)

Under `--watch`, `--diff-only` replaces the full results table on every
tick after the first with just what changed since the previous one —
devices added, devices removed, and per-field changes (a different port, a
newly risky port, etc.) on devices present in both:

```
python network_scanner.py --watch 300 --diff-only
```

This complements `--quiet` (see [[Quiet Mode & Doctor|Quiet-Mode-and-Doctor]])
rather than duplicating it: `--quiet` suppresses a *boring* tick entirely,
while `--diff-only` makes an *interesting* tick's output shorter. The very
first tick still prints the full table, since there's no previous tick to
diff against. Combine both for the quietest possible long-running monitor:

```
python network_scanner.py --watch 300 --diff-only --quiet
```

## Recovering from a flaky scan (`--retries`)

A single dropped ARP/ping reply (or one flaky TCP connect on the mobile
script) can make a device that's genuinely still there look "missing" this
run — and then "NEW" again next run once it answers normally. That false
signal pollutes every registry-based feature: NEW/CHG markers, the
missing-device report, IP-conflict alerts, and webhook notifications all
inherit it.

```
python network_scanner.py --retries 1
python mobile_network_scanner.py --retries 2
```

The two scripts implement this differently, matching how each discovers
devices. `network_scanner.py`'s ARP/ping sweep is one broadcast across the
whole subnet, so each retry re-runs that same broadcast and merges in
anything new — scapy's raw sockets aren't necessarily safe to hit
concurrently from several targeted single-host requests instead, so a
second full broadcast is the simple, safe option even though it's less
targeted. `mobile_network_scanner.py` already probes each host
individually over plain TCP, so each retry there only re-probes hosts
still missing a match. Both default to `0` (a single pass).

## IP-conflict / spoofing alerts (`network_scanner.py` only)

The same registry also catches a device's IP being taken over by a
*different* MAC address than last time — a DHCP lease getting handed to a
new device is the ordinary cause, but it's exactly the same signal
something spoofing another device's IP (most notably ARP-poisoning your
router's own address) would produce. A conflicting device prints in
magenta:

```
⚠ 1 device(s) with a suspicious IP handoff:
  192.168.1.50         now bb:bb:bb:bb:bb:bb, previously aa:aa:aa:aa:aa:aa
```

This is a hygiene signal, not an intrusion-detection system — a home
network reassigns leases all the time, and most hits will be completely
benign. A conflict on your router/gateway's own IP is the one case worth
treating as urgent. Only compares devices that both have a real MAC
address — a ping-sweep-only device can't meaningfully conflict with
anything. Not available on `mobile_network_scanner.py`, which has no MAC
address to compare in the first place. Skipped entirely with
`--no-track-devices`.

For continuous (not just per-scan) ARP-spoofing detection, see [[ARP
Monitor|ARP-Monitor]].

## See also

- [[Labels & Registry Backup|Labels-and-Registry-Backup]]
- [[Exporting Results & History|Exporting-Results-and-History]]
- [[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]]
