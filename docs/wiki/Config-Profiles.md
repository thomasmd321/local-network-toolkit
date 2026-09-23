# Config Profiles

Applies to both [[Network Scanner|Network-Scanner]] and [[Mobile Network
Scanner|Mobile-Network-Scanner]].

With 30+ flags on each scanner now, `--profile NAME` loads a named section
from an INI file as new defaults, so a long recurring combination of flags
doesn't need retyping every time:

```
# ~/.network_scanner.ini
[home]
timeout = 2.0
exclude = 192.168.1.5,192.168.1.20/30
log-history = /home/me/scan-history.jsonl
no-color = true
```

```
python network_scanner.py --profile home
```

Any flag given explicitly on the command line still overrides the
profile's value for that run — a profile only changes what a flag falls
back to when it isn't passed at all, so a one-off scan never requires
editing the file first:

```
python network_scanner.py --profile home --timeout 5.0   # profile's timeout=2.0 is overridden
```

`--profile-file FILE` points at a different INI file (default
`~/.network_scanner.ini` / `~/.mobile_network_scanner.ini`); a `--profile`
name not found in it is a usage error rather than silently falling back to
defaults. A repeatable flag (`--set-label`, `--remove-label`) can't be set
from a profile and is skipped if present.

Values are coerced using each flag's own declared argparse type — no
separate, hand-maintained schema of "what's configurable and what type" to
drift out of sync with the flags themselves.

**Security note:** if a profile stores an MQTT password directly (see
[[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]]),
`chmod 600` the profile file — the same exposure `--mqtt-password` on the
command line has applies to any secret sitting in plain text on disk.

## See also

- [[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]]
- [[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]]
