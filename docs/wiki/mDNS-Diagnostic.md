# mDNS Diagnostic (`mdns_diagnostic.py`)

Diagnoses whether mDNS multicast actually works from this device/app.

```
python mdns_diagnostic.py
```

Run this directly and read the output — it isolates each step (socket
creation, binding to port 5353, joining the multicast group, sending a
query, receiving any reply at all) so you can see exactly which layer is
failing, rather than guessing from "no hostname" alone.

This is the tool that confirmed [[Mobile Network
Scanner|Mobile-Network-Scanner]]'s iOS limitation: on a-Shell, every mDNS/
DNS-SD query failed outright with `OSError(65, 'No route to host')` on the
send itself, pointing at iOS's Local Network Privacy model (apps must
declare Bonjour service types at the app-bundle level, which a generic
terminal app running a script typed at runtime can't do) rather than a bug
in either script. If you hit the same error, this is the tool to confirm
it's the platform, not your code or network.

**Fixed a real bug**: Step 5's receive loop used to set a fixed 3.0s
socket timeout once, outside the loop, instead of recomputing it to
whatever's actually left of the budget on each pass. A reply arriving late
in the window (mDNS responders jitter their replies, per RFC 6762) could
make the script run up to ~6s instead of the "3 seconds" it explicitly
tells you it's checking - misleading for a tool whose entire purpose is
timing-isolation diagnosis. Fixed to re-set the timeout to the true
remaining time on every iteration.

## See also

- [[Mobile Network Scanner|Mobile-Network-Scanner]]
- [[mDNS Browser|mDNS-Browser]]
- [[Troubleshooting]]
