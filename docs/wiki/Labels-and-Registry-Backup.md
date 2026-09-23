# Labels & Registry Backup

Applies to both [[Network Scanner|Network-Scanner]] and [[Mobile Network
Scanner|Mobile-Network-Scanner]]. Builds on the known-devices registry
described in [[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]].

## Custom device labels/aliases

Assign a friendly name to a device — useful when its real hostname is
cryptic or blank — with `--set-label KEY=LABEL`, where `KEY` is its MAC
address for `network_scanner.py` (or IP if it has none), or always its IP
for `mobile_network_scanner.py`. The label is stored in the same
known-devices registry, and shown in the results table in place of/
alongside the real hostname (`Kitchen Server (localhost)` when they
differ, just `Kitchen Server` when there's no hostname to show alongside
it).

```
python network_scanner.py --set-label aa:bb:cc:dd:ee:ff="Kitchen Server"
python mobile_network_scanner.py --set-label 192.168.1.42="Kitchen Echo"
python network_scanner.py --remove-label aa:bb:cc:dd:ee:ff
```

Both flags are repeatable and take effect immediately, including on the
scan that runs in the same command. A device doesn't need to already be in
the registry: labeling one by IP/MAC you've seen in a previous run's
output creates a minimal registry entry for it, though that also means it
won't show as `NEW` the next time it's actually scanned (labeling it
counts as "already known"). A label also appears in place of the hostname
in the "previously-seen device(s) not found" report if that device goes
missing later.

## Backing up or moving the registry

Labeling effort (and everything else the registry tracks — first-seen/
last-seen timestamps, ports, etc.) lives only on whichever machine ran the
scans, so `--export-known-devices FILE` copies it out for backup or to
move to a new machine, and `--import-known-devices FILE` merges a
previously-exported file back in:

```
python network_scanner.py --export-known-devices backup.json
python network_scanner.py --import-known-devices backup.json
```

Both exit immediately without scanning. The registry is already a plain
JSON file, so exporting is really just a documented, formatted copy of it
— importing onto a fresh machine's empty registry is a full restore.
Importing onto a registry that already has some entries is a deliberate
"restore from backup," not a symmetric merge: an imported entry wins on a
key collision (e.g. a label edited differently on two machines), while
anything only the current registry knows about is left untouched.

## Excluding devices from a scan

`--exclude IP/CIDR` skips one or more addresses — comma-separated, each
either a bare IP (treated as a /32) or a CIDR range — from the rest of a
scan, without narrowing the whole subnet just to dodge one host: a printer
that crashes under port probes, a NAS you don't want woken from sleep, or
a noisy neighbor you just don't care about.

```
python network_scanner.py --exclude 192.168.1.5
python network_scanner.py --exclude 192.168.1.5,192.168.1.10
python network_scanner.py --exclude 192.168.1.0/28
python mobile_network_scanner.py --exclude 192.168.1.5,10.0.0.0/24
```

On `mobile_network_scanner.py`, exclusion is complete: excluded hosts are
dropped from the list before any TCP connection is ever attempted. On
`network_scanner.py`'s ARP path, the initial ARP broadcast still reaches
every host on the subnet — scapy's `srp()` sends one request across the
whole range in a single call, with no way to carve individual addresses
out of it — but excluded devices are dropped immediately after discovery,
before vendor lookup, port scanning, the risky-ports check, and the final
report/export/tracking, so in practice they're never touched beyond that
one broadcast packet. The ping-sweep fallback still pings every host
itself, applying exclusion the same way right after discovery.

## See also

- [[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]]
- [[Config Profiles|Config-Profiles]] — a `chmod 600` note applies to any
  profile file storing sensitive values too
