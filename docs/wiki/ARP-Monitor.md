# ARP Monitor (`arp_monitor.py`)

The IP-conflict alert built into [[Network Scanner|Network-Scanner]] (see
[[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]])
only samples at scan time — a full scan every few minutes at best under
`--watch` — so a live man-in-the-middle attack happening *between* scans
can go unnoticed until the next one, if ever. This watches continuously
instead: every ARP reply on the wire is observed as it happens, and any IP
whose MAC changes mid-session is flagged immediately.

```
python arp_monitor.py                     # watch the default interface
python arp_monitor.py --interface eth0
python arp_monitor.py --log conflicts.jsonl
```

Needs `scapy` and the same raw-socket privileges (root/administrator) as
`network_scanner.py`'s ARP scan — there's no way to passively observe ARP
traffic without them. Like the IP-conflict alert it complements, this is a
hygiene/detection aid, not a full intrusion-detection system: a MAC change
is exactly as likely to be an ordinary DHCP lease reassignment as an
actual attack, and it can't catch spoofing already fully established
before it started watching. A change on your router/gateway's own IP is
the one case worth treating as urgent.

## Known limitation, stated plainly

This project's own development environment has a broken scapy/cryptography
install (see `--doctor` in [[Network Scanner|Network-Scanner]]) and no
raw-socket privileges either, so the actual packet-sniffing path has never
run for real in this environment. The pure detection logic it calls
(`process_arp_observation()`) is fully unit-tested and needs nothing from
scapy at all; the `sniff()` wiring around it is verified only by faking out
the scapy import in tests, not against real ARP traffic on real hardware.

## See also

- [[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]] — the scan-time equivalent of this continuous monitor
- [[DHCP Monitor|DHCP-Monitor]] — a different, complementary class of LAN trouble
- [[Troubleshooting]]
