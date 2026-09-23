# Getting Started

No installation step is required — every script in this repo is a single
standalone `.py` file with no required third-party dependency. Clone the
repo, or grab just the file you need, and run it with Python 3.9+.

```
git clone https://github.com/thomasmd321/local-network-toolkit.git
cd local-network-toolkit
python3 network_scanner.py
```

## Optional dependencies (desktop/server only)

[[Network Scanner|Network-Scanner]] and [[ARP Monitor|ARP-Monitor]] work out
of the box, but get faster/more capable with two purely optional packages:

```
pip install scapy   # enables a fast ARP scan (returns MAC addresses) -
                     # also required for arp_monitor.py entirely
pip install psutil  # enables --all-subnets (interface enumeration)
```

Neither is required for [[Mobile Network Scanner|Mobile-Network-Scanner]] or
any of the other standalone tools.

## Running on iPhone (a-Shell)

[[Mobile Network Scanner|Mobile-Network-Scanner]] needs nothing beyond
plain sockets, so it runs unmodified in a sandboxed Python runtime. Install
[a-Shell](https://apps.apple.com/us/app/a-shell/id1473805438) from the App
Store (not "a-Shell mini," which strips out `git`), then either clone the
whole repo or grab just the one file you need:

```
curl -O https://raw.githubusercontent.com/thomasmd321/local-network-toolkit/main/mobile_network_scanner.py
python3 mobile_network_scanner.py
```

The first mDNS query may trigger an iOS prompt asking to allow "Local
Network" access — accept it, though see [[Mobile Network
Scanner|Mobile-Network-Scanner]] and [[mDNS Diagnostic|mDNS-Diagnostic]] for
why mDNS/DNS-SD specifically still won't work on iOS even after accepting.

## A five-minute tour

```
python3 network_scanner.py                       # who's on my network right now
python3 network_scanner.py --watch 300 --quiet    # leave running: alert only when something changes
python3 network_scanner.py --doctor               # check this environment's capabilities first
```

From there:
- [[Known-Device Tracking & Watch Mode|Known-Device-Tracking-and-Watch-Mode]]
  explains the NEW/CHG markers `--watch` produces.
- [[Notifications, Metrics & MQTT|Notifications-Metrics-and-MQTT]] covers
  getting pinged (webhook), graphed (Prometheus), or turned into a Home
  Assistant presence sensor (MQTT) instead of just watching a terminal.
- [[Config Profiles|Config-Profiles]] covers saving a long flag combination
  instead of retyping it.

## Shell completion

`completions.bash` adds bash tab-completion for every script's flag names —
see [[Shell Completion|Shell-Completion]].

```
source /path/to/local-network-toolkit/completions.bash
```

## Running the tests

```
pip install -r requirements-dev.txt
pytest
```

See [[Testing & CI|Testing-and-CI]] for what's mocked vs. run for real.
