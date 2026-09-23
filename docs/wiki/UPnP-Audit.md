# UPnP Audit (`upnp_audit.py`)

[[Exposure Check|Exposure-Check]] answers "is this port reachable from
outside" after the fact, by probing your public IP. This answers a
sharper, earlier question: *why* a port might be open at all, even though
nothing in a LAN scan looks unusual. Many home routers ship with UPnP
enabled, letting any device on the network ask the router to forward a
port from the internet straight to itself — a game console, a BitTorrent
client, a smart-home hub — with no further confirmation and no trace
visible from LAN-side scanning at all. This queries the router itself for
its current UPnP port-mapping table, the same information a device could
have used to open that port in the first place.

```
python upnp_audit.py
python upnp_audit.py --timeout 5
python upnp_audit.py --output mappings.json
```

Works in three steps: SSDP multicast discovery finds your router's UPnP
Internet Gateway Device (the same request/response shape mDNS/DNS-SD's
own discovery is built on, an older HTTP-header-flavored sibling
protocol); its XML device description is fetched and walked — regardless
of nesting depth, since routers vary here — to find the WANIPConnection or
WANPPPConnection service that actually manages port forwarding; then that
service's `GetGenericPortMappingEntry` SOAP action is called once per
index until the router reports there are no more. A mapping forwarding a
port already on `RISKY_PORTS` is called out specifically, the same
hygiene-flagging spirit as the risky-ports check elsewhere in this
project.

## Known limitation, stated plainly

This project's own development environment has no reachable UPnP Internet
Gateway Device. The full SSDP → XML → SOAP pipeline is verified against a
real, unmocked gateway simulated locally — a genuine SSDP responder plus a
genuine HTTP server serving real XML/SOAP bodies, all communicating over
real sockets, no mocks anywhere in that chain — which exercises every
wire-format detail this script depends on, but it has never spoken to an
actual router. Router UPnP stacks are inconsistent about spec compliance
in ways a simulated one won't reproduce; treat a first real run as the
verification it hasn't had yet.

## See also

- [[Exposure Check|Exposure-Check]]
- [[Troubleshooting]]
