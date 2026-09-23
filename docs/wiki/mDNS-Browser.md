# mDNS Browser (`mdns_browser.py`)

The two scanners only ever ask mDNS/DNS-SD one narrow question at a time —
"what's this IP's hostname?" or "is anything answering as a Chromecast?"
This asks the broader one: what services exist on this network at all —
printers, AirPlay speakers, SSH-capable hosts, HomeKit accessories,
anything advertising itself — without needing to already know an IP or
guess a service type up front.

```
python mdns_browser.py                          # discover + browse everything found
python mdns_browser.py --timeout 3
python mdns_browser.py --services _http._tcp.local,_ipp._tcp.local
python mdns_browser.py --no-discover             # skip auto-discovery, use built-ins only
python mdns_browser.py --output services.json
```

It works in two phases. First, it asks DNS-SD's own "meta-query"
(`_services._dns-sd._udp.local`, RFC 6763 §9) which service types are
actually in use on the network — not every device implements this even
when it implements browsing for its own type, so the result is unioned
with a small built-in list of common types (Chromecast, AirPlay, IPP
printers, SMB, SSH, HomeKit, and more — see `_COMMON_SERVICE_TYPES`).
Second, it browses all of those types at once on a single socket, joining
each response's PTR/SRV/A records into an `{ip: name}` map per type — the
same join [[Mobile Network Scanner|Mobile-Network-Scanner]]'s own
`mdns_service_lookup()` does for Chromecast specifically, generalized here
to many types in one pass.

Like the mDNS code in the two scanners, this is best-effort (one query per
type, reading whatever comes back within `--timeout`) and shares their iOS
limitation — mDNS/DNS-SD sends fail outright there due to Apple's Local
Network Privacy model. See [[Mobile Network
Scanner|Mobile-Network-Scanner]]'s "Known limitation on iOS" section and
[[mDNS Diagnostic|mDNS-Diagnostic]].

**Hardened against a real DoS**: `_decode_dns_name()`'s compression-pointer
handling had no cycle guard until a repo-wide review caught it — two
pointers referencing each other (a malformed or hostile packet from any
device on the LAN) caused a genuine, reproduced infinite loop, hanging
this script indefinitely on one bad response. Fixed by tracking visited
pointer offsets and treating a revisited offset as the end of a truncated
name, the same graceful-degrade-on-malformed-data spirit
`_iter_mdns_records()` already used elsewhere in this function's own file.
The identical fix landed in [[Network Scanner|Network-Scanner]], [[Mobile
Network Scanner|Mobile-Network-Scanner]], and [[DNS Check|DNS-Check]],
which all duplicate this same decoder.

## See also

- [[mDNS Diagnostic|mDNS-Diagnostic]]
- [[Mobile Network Scanner|Mobile-Network-Scanner]]
