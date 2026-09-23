# Windows ARP/DHCP Watch (`win_arp_dhcp_watch.py`)

[[ARP Monitor|ARP-Monitor]] and [[Network Scanner|Network-Scanner]]'s ARP
scan both need scapy plus raw-socket privileges — root/administrator, plus
Npcap on Windows specifically — to sniff or send ARP packets directly. But
Windows already maintains its own ARP cache and DHCP lease records,
readable through two ordinary, unprivileged commands every Windows
install ships with: `arp -a` and `ipconfig /all`. This polls both
periodically instead of sniffing packets, for a locked-down/managed
Windows machine where installing Npcap or getting administrator rights
isn't realistic.

```
python win_arp_dhcp_watch.py
python win_arp_dhcp_watch.py --interval 10 --log alerts.jsonl
python win_arp_dhcp_watch.py --no-color
```

Two independent checks each poll:

- **ARP cache diffing** — the identical signal [[ARP
  Monitor|ARP-Monitor]]'s own detection logic catches (an IP answering
  from an unfamiliar MAC), just sourced from `arp -a` snapshots instead
  of live sniffed packets — trading "catches it instantly" for "catches
  it within one poll interval, no setup burden." `process_arp_observation()`
  is duplicated verbatim from `arp_monitor.py`.
- **DHCP-server-per-adapter diffing** — a different vantage point than
  [[DHCP Monitor|DHCP-Monitor]]'s passive sniffing: instead of watching
  the wire for any server's broadcasts, this asks Windows itself, per
  adapter, which DHCP server *it* actually got its own lease from
  (parsed from `ipconfig /all`), and flags when that answer changes.

**Windows-only by design** — `ipconfig /all`'s DHCP-lease fields have no
equivalent on Linux/macOS in this project, the same kind of deliberate
platform split as [[Wi-Fi Scanner|Wifi-Scanner]] and [[Traceroute
Mapper|Traceroute-Mapper]]. Running this on another OS prints a clear
error and exits rather than attempting a partial/wrong-format parse.

## Known limitation, stated plainly

This project's own development environment is Linux, with no real
Windows machine to run this against — genuinely untestable end to end the
way most tools here manage. Every parsing/diffing function
(`parse_arp_a_output()`, `parse_ipconfig_all()`,
`process_arp_observation()`, `find_dhcp_server_changes()`) is
unit-tested against hand-built output matching each command's documented
format, and the full subprocess → parse → diff → print pipeline was run
for real (`platform.system()` patched to report "Windows", with real fake
`arp`/`ipconfig` scripts on `PATH` so `subprocess.run()` genuinely
executes something) — confirming two consecutive polls correctly detect
both an ARP MAC change and a DHCP server change. This caught and fixed a
real regex bug before it shipped: a naive `\s*\.*\s*` can't match
`ipconfig /all`'s *alternating* space-dot-space-dot padding before each
field's colon (it only allows one block of whitespace then one block of
dots), fixed with a single `[\s.]*` character class instead. Still
unverified: the real `arp.exe`/`ipconfig.exe` on an actual Windows
install, and their real output format.

## See also

- [[ARP Monitor|ARP-Monitor]]
- [[DHCP Monitor|DHCP-Monitor]]
- [[Troubleshooting]]
