# Notifications, Metrics & MQTT

Three ways to surface a `--watch` loop's findings without watching a
terminal, applying to both [[Network Scanner|Network-Scanner]] and [[Mobile
Network Scanner|Mobile-Network-Scanner]].

## Webhook notifications

`--notify-webhook URL` POSTs a plain-text summary to `URL` as `{"text":
"..."}` JSON — the format Slack's incoming webhooks (and many other
generic webhook receivers, including most self-hosted alerting tools)
expect directly — whenever a scan has a NEW device, a port change, a
missing device, or a risky port to report. A boring scan sends nothing at
all, the same trigger condition `--quiet` uses (see [[Quiet Mode &
Doctor|Quiet-Mode-and-Doctor]]).

```
python network_scanner.py --watch 300 --notify-webhook https://hooks.slack.com/services/...
python mobile_network_scanner.py --watch 300 --notify-webhook https://ntfy.sh/your-topic
```

A failed or unreachable webhook prints a warning to stderr and the scan
continues normally — it never crashes the run. This deliberately doesn't
special-case any one service's exact payload shape; a target expecting
something else (Discord's `content` key, ntfy.sh's plain-text body) may
need a small relay in between, or just point it at a service that already
speaks the Slack-compatible format.

## Prometheus metrics (`--metrics-file`)

`--metrics-file FILE` writes each scan's summary counts to `FILE` in
Prometheus text exposition format, ready for `node_exporter`'s textfile
collector to pick up — turning any always-on `--watch` box into a
Grafana-graphable metrics source with no new runtime dependency:

```
python network_scanner.py --watch 300 --metrics-file /var/lib/node_exporter/textfile_collector/network_scanner.prom
```

`network_scanner.py` writes `network_scanner_devices_total`,
`network_scanner_devices_new_total`, `network_scanner_devices_risky_total`,
`network_scanner_ip_conflicts_total`, and
`network_scanner_last_scan_timestamp_seconds`; `mobile_network_scanner.py`
writes the same set (`mobile_network_scanner_...`) minus the IP-conflicts
metric, since it has no MAC address to compare against and so nothing to
report a count for (see [[Known-Device Tracking &
Watch Mode|Known-Device-Tracking-and-Watch-Mode]]). The file is written
atomically — a temp file, then renamed into place — since `node_exporter`
polls the textfile-collector directory on its own schedule, independent
of when a scan happens to be mid-write. Unlike `--notify-webhook`, this
writes on every tick regardless of `--quiet` or whether anything changed —
"0 new devices" is itself meaningful data to a dashboard.

## MQTT / Home Assistant presence publishing

`--mqtt-host HOST` publishes each scan's results to an MQTT broker as Home
Assistant MQTT Discovery presence sensors, so `--watch` can act as a real
presence sensor in a home automation setup instead of just a terminal log:

```
python network_scanner.py --watch 300 --mqtt-host 192.168.1.10
python mobile_network_scanner.py --watch 300 --mqtt-host 192.168.1.10 --mqtt-username bob --mqtt-password-file ~/.mqtt_password
```

Every device found becomes a `binary_sensor` entity (`device_class:
"presence"`) in Home Assistant automatically the first time it's
published — no manual YAML entity configuration needed. A device that
drops out of a later scan is actively published `OFF` (using the same
"previously-seen device(s) not found" data), rather than just silently no
longer being republished and left showing its stale last state.

Other flags: `--mqtt-port` (default 1883), `--mqtt-client-id` (defaults to
`network_scanner`/`mobile_network_scanner`, so both scripts can safely
publish to the same broker without colliding), and
`--mqtt-discovery-prefix` (default `homeassistant`, matching Home
Assistant's own default). A failed publish (unreachable broker, bad
credentials) prints a warning to stderr and never crashes the scan. This
is implemented as a small, from-scratch, publish-only MQTT 3.1.1 client
(stdlib `socket` only, no new dependency) — the same "implement the wire
protocol yourself" approach this project already takes for DHCP/DNS/UPnP.

### Keeping the MQTT password off the command line

`--mqtt-password` on the command line is visible to any other user on the
same machine via `ps aux`, and lingers in shell history. Prefer
`--mqtt-password-file FILE` (its contents, trimmed of surrounding
whitespace) or the `MQTT_PASSWORD` environment variable instead — resolved
in that order, with an explicit `--mqtt-password` always taking priority
if given:

```
echo "secret" > ~/.mqtt_password && chmod 600 ~/.mqtt_password
python network_scanner.py --watch 300 --mqtt-host 192.168.1.10 --mqtt-password-file ~/.mqtt_password
MQTT_PASSWORD=secret python network_scanner.py --watch 300 --mqtt-host 192.168.1.10
```

The same exposure applies to a `--profile` INI file that stores an MQTT
password directly — see [[Config Profiles|Config-Profiles]] — `chmod 600`
it too.

### TLS

`--mqtt-tls` connects over TLS (port 8883 on most brokers) instead of
plain TCP:

```
python network_scanner.py --watch 300 --mqtt-host mqtt.example.com --mqtt-port 8883 --mqtt-tls
```

A typical home broker's self-signed certificate will fail the default
certificate/hostname verification; `--mqtt-insecure-tls` skips it (still
encrypted, just no longer verifying who's on the other end — fine on a
trusted LAN, not recommended over the open internet).

### Availability

Publishing device presence has no way to expire on its own — if the
script crashes, the machine loses power, or `--watch` is killed mid-loop,
Home Assistant keeps showing every device's last-published state forever.
By default, every `--mqtt-host` run also publishes to a shared
`{prefix}/{client-id}/availability` topic (`online` right after
connecting) and sets it as this connection's MQTT Last Will (`offline`,
delivered by the broker automatically if the connection ever drops
without a clean disconnect) — each entity's discovery config points at
this topic, so Home Assistant marks it "unavailable" the moment this
script itself stops running, instead of silently trusting a state that
may be hours old. `--mqtt-no-availability` turns this off if you'd rather
not have it.

## See also

- [[Quiet Mode & Doctor|Quiet-Mode-and-Doctor]]
- [[Config Profiles|Config-Profiles]] — save any combination of the flags above as a named profile
- [[Network Dashboard|Network-Dashboard]] — a fourth option, a glanceable web page instead of push/metrics/MQTT
