# Traceroute Mapper (`traceroute_mapper.py`)

Neither [[Exposure Check|Exposure-Check]]'s "is this port reachable" nor
[[Wi-Fi Scanner|Wifi-Scanner]]'s "is my signal weak" tells you *where*
along the path a slow connection is actually slow. This does: it wraps the
OS's own traceroute tool and reports every hop's IP, hostname, and
round-trip time.

```
python traceroute_mapper.py 8.8.8.8
python traceroute_mapper.py google.com --max-hops 20
python traceroute_mapper.py 192.168.1.1 --no-resolve-hostnames
python traceroute_mapper.py 8.8.8.8 --output path.json
```

Runs each platform's tool in numeric-only mode — `traceroute -n` on
Linux/macOS, `tracert -d` on Windows — specifically to sidestep the
biggest source of cross-platform output differences, then resolves each
hop's hostname itself afterward via plain reverse DNS, rather than
depending on the traceroute binary's own often-inconsistent DNS handling.
A hop that timed out on every probe still shows up (with no IP, three
missed replies) rather than being silently dropped, so a gap in the path
stays visible; a hop whose best RTT is notably high is called out in the
output.

## Known limitation, stated plainly

This project's own development environment has no `traceroute`/`tracert`
binary at all, so every platform's parser is verified only against mocked
command output matching each tool's documented format (plus one real
subprocess run against a fake `traceroute` script on `PATH`) — never
against a real path on real hardware, on any of the three platforms.
Traceroute output varies more between tool versions/distros than most
formats parsed elsewhere in this project; treat a first real run as the
verification it hasn't had yet.

## See also

- [[Exposure Check|Exposure-Check]]
- [[Troubleshooting]]
