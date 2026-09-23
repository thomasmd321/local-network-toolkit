# DNS Check (`dns_check.py`)

Every other tool here assumes DNS answers can be trusted. A compromised
router, a malicious/free Wi-Fi hotspot, or a captive portal commonly
intercept DNS and answer with their own IP for domains that should
NXDOMAIN — redirecting to an ad page, a phishing page, or a "please log
in" portal before a browser is even opened.

```
python dns_check.py                       # both checks, default public resolvers
python dns_check.py --resolver 1.1.1.1 --resolver 9.9.9.9
python dns_check.py --output dns_check.json
```

Two checks:

- **The decisive one** queries a fresh random hostname under the
  `.invalid` TLD (reserved by RFC 2606 so it can never be a real domain) —
  any answer at all, from your resolver or a public one, means something
  is fabricating NXDOMAIN responses.
- **The softer, caveated one** compares `example.com` (also RFC
  2606-reserved, for stable documentation use) across your resolver and a
  few public ones (Cloudflare, Google, Quad9 by default) and flags a
  mismatch — worth a second look, not proof on its own, since a proxying/
  filtering resolver or a stale cache can also cause this.

Public resolvers are queried directly with a from-scratch DNS client over
raw UDP sockets (stdlib only), since `socket.getaddrinfo()` only ever asks
whatever the OS itself is configured to use.

## Verification

Verified about as thoroughly as a tool here can be: the wire-format code
is exercised against a real, unmocked local fake DNS server, and — since
raw UDP port 53 traffic isn't blocked by this sandbox's outbound proxy the
way HTTPS is — a real run against the actual Cloudflare/Google/Quad9
resolvers worked end to end too, correctly returning NXDOMAIN for a fresh
canary and agreeing on `example.com`'s real answer.

**Hardened against a real DoS**: `_decode_dns_name()` had no guard against
a DNS compression-pointer cycle until a repo-wide review caught and fixed
it — a real, reproduced infinite loop, and in this tool's case reachable
by exactly the kind of hijacking/malicious resolver it exists to detect
(transaction-ID matching doesn't block it, since a hijacking resolver is
genuinely answering your query, just falsely). See [[mDNS
Browser|mDNS-Browser]] for the fix's details, shared verbatim across all
four scripts with this decoder.

## See also

- [[Troubleshooting]]
