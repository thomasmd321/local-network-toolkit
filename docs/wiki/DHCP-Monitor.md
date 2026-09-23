# DHCP Monitor (`dhcp_monitor.py`)

A different class of LAN trouble than ARP spoofing: an unauthorized DHCP
server handing out its own leases alongside (or instead of) your real
router — a classic attack (hand out a malicious gateway/DNS server to
every new client), or an equally common accident (a consumer router
plugged in backwards, its own DHCP server now answering on your LAN).
Nothing else here would ever notice — a device scan sees who's *on* the
network, not who's been quietly handing out its addresses.

```
python dhcp_monitor.py                          # first server seen is the trusted baseline
python dhcp_monitor.py --trusted-server 192.168.1.1
python dhcp_monitor.py --log rogue_dhcp.jsonl
```

Unlike [[ARP Monitor|ARP-Monitor]], this needs no scapy or raw sockets at
all — DHCPOFFER/DHCPACK replies are ordinary broadcast UDP on port 68 (the
client port), so an ordinary socket bound there receives them the same way
a real DHCP client does. On Linux/macOS this still needs root: port 68 is
a privileged port there regardless of socket type. Windows doesn't gate
ports under 1024 on administrator status the same way, but that's not the
same as "just works" there — it'd be sharing port 68 with Windows' own
DHCP Client service, and Windows' looser `SO_REUSEADDR` semantics make
whether that bind actually succeeds genuinely untested. The first server
observed (or any named with `--trusted-server`) is the assumed-good
baseline; any additional, distinct server after that is flagged.

## Verification

Verified more thoroughly than [[ARP Monitor|ARP-Monitor]] could manage:
the wire-format parsing and detection logic are unit-tested with
hand-built packets, the socket-receive loop is verified end to end against
a real, unmocked UDP socket on a non-privileged test port, and — since
this project's own sandbox happens to run as root on Linux — the real
production path was also run for real there, against the genuine
privileged port 68, correctly ignoring a trusted server and flagging an
untrusted one. What's still unverified is real DHCP traffic from a real,
physical network (every packet used above was hand-built to match the RFC
2131 wire format, not captured from an actual router), and the entire
Windows path, including whether the port-68 bind even succeeds there
alongside the built-in DHCP Client service.

## See also

- [[ARP Monitor|ARP-Monitor]]
- [[Troubleshooting]]
