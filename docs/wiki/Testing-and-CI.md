# Testing & CI

```
pip install -r requirements-dev.txt
pytest
```

Unit tests mock nearly all network/subprocess calls (a handful instead use
a real loopback socket this same machine both opens and connects to), so
the full suite runs without any real *external* network access or
elevated privileges.

A GitHub Actions workflow (`.github/workflows/tests.yml`) runs the same
suite on every push and pull request, across Python 3.9–3.12.

## What's mocked vs. verified for real

This project leans heavily on real, unmocked verification wherever the
sandbox allows it — a real loopback socket, a real fake broker/server
thread, a real hand-built packet — rather than trusting a mock alone for
anything wire-format-sensitive. Where a tool genuinely can't be verified
against real hardware/network conditions in this project's own development
environment (no scapy privileges, no UPnP gateway, no Wi-Fi hardware, no
`traceroute` binary), that's called out explicitly as a **known
limitation** on that tool's own wiki page rather than left implicit — see
[[Troubleshooting]] for the full list.

Examples of the real-verification approach:
- [[LAN Throughput|LAN-Throughput]]: every test uses real, unmocked
  sockets — two genuinely separate processes talking over real loopback
  TCP.
- [[DHCP Monitor|DHCP-Monitor]] and [[DNS Check|DNS-Check]]: the
  socket-receive loop / wire-format client is verified against a real,
  unmocked UDP socket.
- [[UPnP Audit|UPnP-Audit]]: verified against a real, unmocked simulated
  gateway (a genuine SSDP responder plus a genuine HTTP server), though
  never a real router.
- MQTT (see [[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]]):
  a real fake MQTT broker over a real loopback socket confirms the actual
  wire bytes `publish_mqtt()` sends, including Last Will bits and TLS
  socket wrapping.

## See also

- [[Troubleshooting]]
