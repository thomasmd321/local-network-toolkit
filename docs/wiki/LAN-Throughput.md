# LAN Throughput (`lan_throughput.py`)

None of the other tools here measure this at all: "my internet feels slow"
and "my LAN itself is slow" are different problems, and only a real
transfer between two devices on the same network tells you which one you
actually have.

```
python lan_throughput.py --serve                    # on the receiving machine
python lan_throughput.py --serve --port 6000 --once
python lan_throughput.py --client 192.168.1.50       # on the sending machine
python lan_throughput.py --client 192.168.1.50 --duration 10 --port 6000
```

Plain TCP sockets, no dependency: one machine listens and reports what it
received; the other streams random data at it for a fixed duration
(random, not zeros, since some links compress a repeating pattern in a way
that would over-report the result) and reports what it actually managed to
send. This measures TCP goodput between exactly these two processes, not
raw link-layer bandwidth or a multi-stream aggregate the way a dedicated
tool like `iperf3` does — treat it as a quick, no-install sanity check,
not a substitute for `iperf3` when you need a rigorous number.

## Verification

The most thoroughly verified tool in this project: every test uses real,
unmocked sockets (a real loopback listener and a real client, not a single
mock in the whole test file), and it was also verified through two
genuinely separate `python3 lan_throughput.py` processes talking over real
loopback TCP end to end via the actual CLI, confirming both sides agree on
the exact byte count transferred.

## See also

- [[Traceroute Mapper|Traceroute-Mapper]] — where along the path a slow connection is slow
