# Exposure Check (`exposure_check.py`)

`RISKY_PORTS` elsewhere in this project flags a port from inside the LAN —
but a risky port reachable only from your own network is a much smaller
problem than the same port reachable from the whole internet. This asks
the sharper question: is a LAN-risky port (or any port you name) also
reachable from the outside, by probing your own public IP from this
machine.

```
python exposure_check.py                        # RISKY_PORTS, auto-detected public IP
python exposure_check.py --ports 22,80,443,8080
python exposure_check.py --ip 203.0.113.5 --ports 22
python exposure_check.py --output exposure.json
```

Your public IP is found with a single plain HTTP(S) request to
[api.ipify.org](https://www.ipify.org) — a small, purpose-built "what's my
IP" echo service, no account or API key needed. No other data about your
network is sent anywhere; `--ip` skips this request entirely if you'd
rather not make it, or already know the address.

## Read this before trusting a result

Probing your own public IP from inside your own LAN is **not** a reliable
substitute for a real external scan. Home routers implement NAT loopback/
hairpinning inconsistently — some silently drop this traffic (a genuinely
open port reports as a false "closed" here), others loop it back to a LAN
device without truly routing it to the internet and back (a false "open"
that doesn't prove an actual outside host could reach it). A closed result
here is never proof of safety, and an open result is never definitive
proof of exposure — both need confirming from a real external vantage
point (a VPS, a friend's network, a phone on cellular data with Wi-Fi off,
or a third-party online port-checking site you choose yourself) before
acting on either one. This tool is a cheap first pass, not the final
word — the CLI itself prints this same caveat after every run.

**Fixed a real bug**: `get_public_ip()` didn't catch
`http.client.IncompleteRead` (raised when the connection to
api.ipify.org drops mid-response) - it subclasses `Exception` directly,
not `OSError`, so it slipped past the existing error handling and crashed
the script with a raw traceback instead of the intended, clean error
message every other network failure here produces.

## See also

- [[UPnP Audit|UPnP-Audit]] — answers *why* a port might be open in the first place
- [[Troubleshooting]]
