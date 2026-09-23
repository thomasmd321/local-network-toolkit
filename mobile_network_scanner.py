#!/usr/bin/env python3
"""Discover devices on the local network from a sandboxed environment (e.g. iOS).

network_scanner.py relies on `subprocess` (to shell out to `ping`/`arp`) and
optionally raw sockets (scapy's ARP scan). Sandboxed Python runtimes such as
iOS apps (Pythonista, a-Shell, Pyto) allow neither: no spawning external
processes, no raw sockets. This script instead discovers hosts by attempting
plain TCP connections to a handful of commonly-open ports, which only needs
an ordinary client socket and works anywhere Python's `socket` module does.

It will not find hosts with none of the probed ports open or reachable
(e.g. a phone with all inbound connections blocked), so it's a best-effort
discovery method, not a guarantee of completeness the way an ARP scan is.

Hostnames come from, in order: DNS-SD Cast service discovery (see
mdns_service_lookup()) for anything answering on the Chromecast control
port, since Google's Cast devices generally skip the next method; plain
reverse DNS; then mDNS/Bonjour reverse lookup (see mdns_reverse_lookup())
for devices - smart speakers, printers, and most other consumer/IoT gear
- that never register a PTR record but do announce a ".local" name over
multicast. None of this needs an external library (nothing like
`zeroconf` reliably builds in these sandboxes); it speaks just enough of
the mDNS/DNS-SD wire protocol directly.

Note on scanning multiple subnets: unlike network_scanner.py, this script
can't auto-detect every subnet a device is attached to - listing network
interfaces requires OS APIs (or the `psutil` package, which needs a C
compiler to build and generally isn't available in these sandboxes) that
iOS's sandbox doesn't expose. It also matters less here: a phone typically
has just one active local network (Wi-Fi) at a time. If you do know of more
than one subnet to check (e.g. your Wi-Fi range and a VPN range), pass them
as a comma-separated list and this script will scan each of them.

Every scan is also compared against a small local registry of previously
seen devices (see _mark_new_devices()), so a device that's never shown up
before gets flagged "NEW" in the results table. Pair this with --watch to
turn a one-shot scan into a lightweight "alert me when something joins my
network" monitor - though note this script has no MAC address to key on
(see _device_identity()), so a device is tracked by IP alone, and a DHCP
lease change will make it look "new" again.

Usage:
    python mobile_network_scanner.py                    # auto-detect local subnet
    python mobile_network_scanner.py 192.168.1.0/24      # scan a specific subnet
    python mobile_network_scanner.py 192.168.1.0/24,10.0.0.0/24  # scan several
    python mobile_network_scanner.py --timeout 0.5 --ports 22,80,443
    python mobile_network_scanner.py --watch 300         # rescan every 5 minutes,
                                                          # flagging newly-seen devices
"""

import argparse
import configparser
import csv
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, TypedDict


class Device(TypedDict):
    """A single discovered device, as returned by tcp_scan()."""

    ip: str
    hostname: str
    # The first port from the probe list that accepted a connection. This
    # is often a useful fingerprint on its own for a device with no
    # hostname - see PORT_SERVICES below - though it's only ever *one*
    # open port, not a full list of everything the device is listening on.
    port: int
    # Whatever grab_banner() read back from that port - an HTTP Server:
    # header, an SSH version string, etc. - or "" if nothing useful came
    # back. Often identifies a device outright when hostname is blank.
    banner: str
    # Filled in by _attach_risky_ports() from _find_risky_ports(): every
    # open port from RISKY_PORTS, not just the first one found (unlike
    # "port" above, which stops at the first match from ports/
    # DEFAULT_PORTS and could otherwise miss a risky port entirely).
    # Empty if none of RISKY_PORTS are open, the common case.
    risky_ports: List[int]


# Ports likely to be open on common home/office devices, so a scan finds
# something useful without the caller having to know what to look for:
#   80, 443, 8080, 8443 - web UIs (routers, printers, smart-home hubs, IoT)
#   22                  - SSH (computers, NAS boxes, routers)
#   445, 139            - Windows/SMB file sharing
#   3389                - RDP (Windows remote desktop)
#   5000, 7000          - common dev-server / media-app ports (e.g. AirPlay)
#   62078               - Apple's "lockdownd" service (iPhones/iPads)
# This is a heuristic, not an exhaustive list - use --ports to override it
# if the devices you're looking for listen on something else. A few more
# worth trying for devices that don't show up above (pass them via
# --ports, comma-separated alongside these): 53 (DNS), 554 (RTSP/cameras),
# 1900 (SSDP/UPnP), 5353 (mDNS/Bonjour), 8009 (Chromecast).
DEFAULT_PORTS: Sequence[int] = (80, 443, 22, 445, 139, 8080, 8443, 62078, 3389, 5000, 7000)

# Short, human-readable labels for well-known ports, used only to annotate
# the results table - a hint at what a device might be, not a certainty
# (lots of devices repurpose these ports, or run several services on
# different ones and only happen to answer on the one we probed first).
# Covers DEFAULT_PORTS plus the extra ports suggested above, so the label
# still shows up if you pass those in via --ports.
PORT_SERVICES: Dict[int, str] = {
    80: "http",
    443: "https",
    22: "ssh",
    445: "smb",
    139: "netbios",
    8080: "http-alt",
    8443: "https-alt",
    62078: "lockdownd (iOS)",
    3389: "rdp",
    5000: "upnp/airplay",
    7000: "airplay",
    53: "dns",
    554: "rtsp (camera/streaming)",
    1900: "ssdp/upnp",
    5353: "mdns/bonjour",
    8009: "chromecast",
}

# Ports where it's worth sending a bare HTTP HEAD request to provoke a
# response, rather than just listening for an unprompted banner - plain
# HTTP and TLS-wrapped HTTP respectively. See grab_banner().
_HTTP_PORTS = frozenset({80, 8000, 8080, 8081})
_HTTPS_PORTS = frozenset({443, 8443})


def get_local_subnet() -> str:
    """Guess the local /24 subnet from the device's primary network interface.

    Returns:
        A CIDR string, e.g. "192.168.1.0/24".
    """
    # Connecting a UDP socket doesn't actually send any packets - it just
    # asks the OS to pick a local address/route for that destination, which
    # is a reliable way to find "my" IP without needing raw-socket or
    # interface-enumeration privileges the sandbox wouldn't grant anyway.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]

    # strict=False lets ipaddress build the containing network even though
    # local_ip is a host address, not the network address itself.
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)


# mDNS/Bonjour's well-known multicast group and port (RFC 6762). Every
# mDNS-speaking device on the local link listens here, regardless of its
# own IP address.
_MDNS_GROUP = ("224.0.0.251", 5353)

# DNS record type numbers used below (from RFC 1035); mDNS reuses the
# ordinary DNS wire format, just delivered over multicast instead of to a
# configured resolver.
_DNS_TYPE_A = 1
_DNS_TYPE_PTR = 12
_DNS_TYPE_SRV = 33
_DNS_CLASS_IN = 1

# The DNS-SD (RFC 6763) service type Chromecasts and other Google Cast
# devices advertise themselves under - this is the exact query the Google
# Home app and Chrome's "Cast" button send to find them, and unlike
# reverse address (in-addr.arpa) lookups, it's not optional: a Cast
# device that didn't answer this wouldn't be discoverable by anything.
_CAST_SERVICE_TYPE = "_googlecast._tcp.local"
# The TCP port a Cast device answers its control protocol on - used only
# to decide whether it's worth asking mdns_service_lookup() at all (see
# tcp_scan()), not for anything protocol-related.
_CAST_CONTROL_PORT = 8009

# mDNS's "QU" flag (RFC 6762 §5.4): setting the top bit of a question's
# class field asks the responder to reply via ordinary unicast UDP,
# straight back to the address/port the query came from, instead of its
# default of multicasting the reply to every device on the link. This
# matters a lot here: our socket below never joins the mDNS multicast
# group or binds to port 5353 (both of which iOS restricts heavily for
# third-party apps), so it can only ever receive a *unicast* reply on the
# ephemeral port it queried from - a multicast-only reply would never
# reach it, even from a device that answered correctly.
_MDNS_QU_BIT = 0x8000


def _encode_dns_name(name: str) -> bytes:
    """DNS-encode a dotted name (e.g. "72.1.168.192.in-addr.arpa") into the
    length-prefixed-label wire format every DNS/mDNS message uses, ending
    in a zero-length label to terminate the name.
    """
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return encoded + b"\x00"


def _decode_dns_name(message: bytes, offset: int) -> Tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at offset in message.

    A DNS name is normally a sequence of length-prefixed labels ending in
    a zero-length label - but to avoid repeating common suffixes (like
    ".local") in every record, a label's length byte can instead have its
    top two bits set (0xC0), meaning "the rest of this name is a copy of
    the name at this other offset in the packet" (a compression pointer).

    Args:
        message: The full raw mDNS message (pointers reference offsets
            into the whole message, not just the current record).
        offset: Where this name starts.

    Returns:
        (dotted_name, offset_after_this_name). The second value is where
        to resume reading the *next* field after this name - which, if
        the name ended in a pointer, is right after that 2-byte pointer,
        not wherever the pointer jumped to.
    """
    labels = []
    return_offset = None  # Where to resume after this name, once known.

    while True:
        length = message[offset]

        if length == 0:
            offset += 1
            break

        if length & 0xC0 == 0xC0:
            # Compression pointer: the low 14 bits (of this byte plus the
            # next one) are the offset to jump to for the rest of the name.
            pointer = struct.unpack(">H", message[offset:offset + 2])[0] & 0x3FFF
            if return_offset is None:
                return_offset = offset + 2
            offset = pointer
            continue

        offset += 1
        labels.append(message[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    return ".".join(labels), return_offset if return_offset is not None else offset


def _build_mdns_ptr_query(qname: str) -> bytes:
    """Build a raw mDNS query packet asking "who is answering to qname?".

    Args:
        qname: The DNS name to query, e.g. a reverse-lookup name like
            "72.1.168.192.in-addr.arpa".

    Returns:
        The raw bytes of a standard DNS query message with one PTR
        question, ready to send to _MDNS_GROUP.
    """
    # Header: transaction ID=0 (fine - we correlate replies by matching
    # the question name instead, and mDNS queries commonly use ID 0),
    # flags=0 (a standard, non-response query), 1 question, 0 answers/
    # authority/additional records.
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    # | _MDNS_QU_BIT: request a unicast reply - see its comment above for
    # why this socket can't rely on the alternative (a multicast reply).
    question = _encode_dns_name(qname) + struct.pack(">HH", _DNS_TYPE_PTR, _DNS_CLASS_IN | _MDNS_QU_BIT)
    return header + question


def _iter_mdns_records(message: bytes):
    """Yield every resource record in an mDNS message, across all sections.

    A DNS/mDNS message has three record sections after its questions
    (answer, authority, additional), and related records for the same
    service are routinely split across them - a device might put its PTR
    answer in "answer" but its supporting SRV/A records in "additional".
    Most one-shot lookups don't care which section a record came from,
    only what type it is, so this walks all of them as a single stream
    rather than making every caller re-implement that traversal.

    Args:
        message: A raw mDNS message, as received over the socket.

    Yields:
        (name, record_type, rdata_offset, rdata_length) for each record,
        in wire order. rdata_offset is an offset into message where that
        record's data starts - decode it with _decode_dns_name() for a
        name-typed record (PTR/SRV/CNAME/...) or read it directly for a
        fixed-format one (A/AAAA/...).
    """
    try:
        question_count, answer_count, authority_count, additional_count = struct.unpack(">HHHH", message[4:12])
    except struct.error:
        return  # Too short to even be a valid DNS header - nothing to yield.

    offset = 12  # DNS header is always exactly 12 bytes.

    # Skip past the question section (present when this "response" is
    # actually another device's query, which we'll see plenty of on a
    # shared multicast channel) to reach the answers.
    for _ in range(question_count):
        _name, offset = _decode_dns_name(message, offset)
        offset += 4  # QTYPE + QCLASS, 2 bytes each.

    for _ in range(answer_count + authority_count + additional_count):
        try:
            name, offset = _decode_dns_name(message, offset)
            record_type, _record_class = struct.unpack(">HH", message[offset:offset + 4])
            offset += 4
            offset += 4  # TTL (4 bytes) - not needed for a one-shot lookup.
            rdata_length = struct.unpack(">H", message[offset:offset + 2])[0]
            offset += 2
        except (struct.error, IndexError):
            return  # Malformed/truncated record - stop rather than guess.

        rdata_offset = offset
        offset += rdata_length
        yield name, record_type, rdata_offset, rdata_length


def _extract_ptr_hostname(message: bytes, qname: str) -> str:
    """Pull a matching PTR record's target hostname out of an mDNS response.

    Args:
        message: A raw mDNS response packet, as received over the socket.
        qname: The name we originally queried for - only an answer for
            this exact name is accepted, so unrelated mDNS chatter on
            the shared multicast channel (there's often a lot of it)
            doesn't get misattributed to the host we asked about.

    Returns:
        The PTR record's target name (e.g. "Chromecast-abc123.local"),
        with its trailing root dot stripped, or "" if this message has
        no PTR answer for qname.
    """
    for name, record_type, rdata_offset, _rdata_length in _iter_mdns_records(message):
        if record_type == _DNS_TYPE_PTR and name.lower().rstrip(".") == qname.lower().rstrip("."):
            hostname, _ = _decode_dns_name(message, rdata_offset)
            return hostname.rstrip(".")

    return ""


def _collect_service_records(message: bytes, host_to_ip: Dict[str, str], instance_to_host: Dict[str, str]) -> None:
    """Pull A and SRV records for a DNS-SD service out of an mDNS response.

    A full "who provides this service, and at what address?" answer is
    normally split across three record types, which is why this fills in
    two separate maps rather than returning one result directly - the
    caller combines them (see mdns_service_lookup()) once every response
    packet has been read, since a device's A and SRV records may not
    even arrive in the same packet.

    Args:
        message: A raw mDNS response packet.
        host_to_ip: Updated in place: hostname (from an A record's own
            name) -> its IPv4 address.
        instance_to_host: Updated in place: service instance name (from
            an SRV record's own name, e.g.
            "Living Room TV._googlecast._tcp.local") -> the hostname it
            runs on (SRV's "target" field).
    """
    for name, record_type, rdata_offset, rdata_length in _iter_mdns_records(message):
        if record_type == _DNS_TYPE_A and rdata_length == 4:
            host_to_ip[name.lower().rstrip(".")] = socket.inet_ntoa(message[rdata_offset:rdata_offset + 4])
        elif record_type == _DNS_TYPE_SRV:
            # SRV rdata is priority(2) + weight(2) + port(2), then the
            # target hostname - we only need the target, not the port,
            # since tcp_scan() already tells us which port answered.
            target, _ = _decode_dns_name(message, rdata_offset + 6)
            instance_to_host[name.rstrip(".")] = target.lower().rstrip(".")


def mdns_reverse_lookup(ip: str, timeout: float) -> str:
    """Look up ip's self-advertised ".local" hostname via mDNS/Bonjour.

    Ordinary reverse DNS (socket.gethostbyaddr) only works for devices
    that have a PTR record in the router/ISP's unicast DNS - which most
    consumer and IoT devices (Chromecasts, smart speakers, printers,
    etc.) never register. Those devices instead announce a hostname over
    mDNS, a multicast UDP protocol every device on the local link can
    see and respond to, so this asks the same "who is this IP?" question
    the same way.

    This needs no special privileges: it's an ordinary UDP socket, not a
    raw one - the same kind of client socket probe_host() already uses -
    so it works in the same sandboxed environments this whole script
    targets. It deliberately never joins the mDNS multicast group or
    binds to port 5353 (both restricted for third-party apps on iOS);
    instead the query sets mDNS's "QU" bit (see _MDNS_QU_BIT) asking the
    responder to reply via plain unicast UDP to our ephemeral port
    instead of its default multicast reply, which this ordinary socket
    can receive just fine. (On iOS specifically, the OS may still prompt
    for "Local Network" permission the first time an app sends this kind
    of query at all - if that's declined, this will just time out and
    return "" like any other non-responding device.)

    Args:
        ip: The target host's IPv4 address.
        timeout: How long to wait for a response, in seconds.

    Returns:
        The advertised hostname (e.g. "Chromecast-abc123.local"), or ""
        if the device didn't respond in time or doesn't support mDNS.
    """
    reversed_octets = ".".join(reversed(ip.split(".")))
    qname = f"{reversed_octets}.in-addr.arpa"
    query = _build_mdns_ptr_query(qname)

    # Tracked as a deadline rather than a single socket timeout, since we
    # may need to read and discard several irrelevant packets (other
    # devices' mDNS traffic) before either finding our answer or running
    # out of time.
    deadline = time.monotonic() + timeout

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # TTL 255 is the mDNS convention so the query reaches every
        # device on the local link, not just ones a few hops away.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        try:
            sock.sendto(query, _MDNS_GROUP)
        except OSError:
            # Multicast send can fail if the sandbox denies local-network
            # access (e.g. iOS permission declined) - treat that the same
            # as "no answer" rather than crashing the whole scan.
            return ""

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ""
            sock.settimeout(remaining)
            try:
                message, _sender = sock.recvfrom(4096)
            except OSError:
                # Covers both a timeout and any other socket error while
                # reading - either way, we're not getting an answer.
                return ""

            hostname = _extract_ptr_hostname(message, qname)
            if hostname:
                return hostname


def mdns_service_lookup(service_type: str, timeout: float) -> Dict[str, str]:
    """Discover every device advertising service_type, mapped by IP address.

    mdns_reverse_lookup() asks "what's your name?" directly, which relies
    on a device having registered a reverse (in-addr.arpa) PTR record -
    an optional feature many device vendors, Google's Cast stack among
    them, simply don't implement. What virtually every mDNS-discoverable
    device *does* implement is DNS-SD (RFC 6763) service advertisement,
    since it's how anything finds them in the first place - a Chromecast
    that didn't answer "who offers _googlecast._tcp.local?" wouldn't be
    castable to from any app. This asks that question instead, once for
    the whole subnet rather than once per IP.

    A full answer needs three record types, usually spread across
    several response packets: a PTR record per device (name ->
    "<friendly name>.<service_type>"), an SRV record per instance
    (that instance name -> the hostname it runs on), and an A record
    per hostname (-> its IP). This collects all of them across every
    response received before the deadline, then joins the three maps
    together at the end.

    Args:
        service_type: A DNS-SD service type, e.g. "_googlecast._tcp.local"
            (see _CAST_SERVICE_TYPE).
        timeout: How long to keep listening for responses, in seconds.
            Unlike mdns_reverse_lookup(), this doesn't return as soon as
            one answer arrives - every matching device on the network
            answers the same broadcast-style query, so cutting off early
            would mean only ever finding the first (or fastest) one.

    Returns:
        A dict of {ip_address: friendly_name}, e.g.
        {"192.168.1.72": "Living Room TV"}, covering only the devices
        that answered and whose PTR/SRV/A records were all received
        before the deadline. Devices that don't offer this service
        simply don't appear - this is not an error.
    """
    query = _build_mdns_ptr_query(service_type)
    deadline = time.monotonic() + timeout

    host_to_ip: Dict[str, str] = {}
    instance_to_host: Dict[str, str] = {}

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            # Service-discovery queries like this one are commonly
            # answered via multicast even when the QU bit (see
            # _MDNS_QU_BIT) is set: unlike a one-shot address lookup,
            # browsing for "everything offering this service" is meant
            # to be a shared, many-listener operation, and many
            # responders (including, apparently, Google's Cast stack)
            # multicast the reply regardless so every browser on the
            # network sees it. Binding to mDNS's own port and joining
            # its multicast group lets us receive that multicast reply,
            # not just a unicast one.
            sock.bind(("", _MDNS_GROUP[1]))
            join_request = struct.pack("4sl", socket.inet_aton(_MDNS_GROUP[0]), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, join_request)
        except OSError:
            # Binding to port 5353 or joining the multicast group can
            # fail - e.g. another process already owns the port without
            # SO_REUSEPORT support, or a sandboxed environment (iOS)
            # restricts it for third-party apps. Fall back to an
            # ordinary ephemeral-port socket relying solely on the QU
            # bit for a unicast reply, same as mdns_reverse_lookup() -
            # worse odds, but still better than giving up outright.
            pass

        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        try:
            sock.sendto(query, _MDNS_GROUP)
        except OSError:
            return {}

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                message, _sender = sock.recvfrom(4096)
            except OSError:
                break
            _collect_service_records(message, host_to_ip, instance_to_host)

    suffix = "." + service_type.lower().rstrip(".")
    results: Dict[str, str] = {}
    for instance_name, host in instance_to_host.items():
        ip = host_to_ip.get(host)
        if ip is None:
            # Its SRV record arrived, but not (yet, or ever) the matching
            # A record - can't map it to an IP, so skip it rather than
            # guess.
            continue
        lower_instance = instance_name.lower()
        friendly_name = instance_name[: -len(suffix)] if lower_instance.endswith(suffix) else instance_name
        results[ip] = friendly_name

    return results


def _resolve_hostname(ip: str, mdns_timeout: float) -> str:
    """Resolve ip to a hostname, trying reverse DNS first and mDNS second.

    Args:
        ip: The target host's IPv4 address.
        mdns_timeout: How long to wait for an mDNS response if the
            ordinary reverse-DNS lookup comes up empty.

    Returns:
        A hostname from whichever method found one first, or "" if
        neither did.
    """
    try:
        # gethostbyaddr does a reverse-DNS (PTR) lookup; on a home
        # network this usually only resolves for the router itself,
        # since consumer devices rarely register PTR records.
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        # No PTR record, or the lookup timed out/failed outright - try
        # mDNS instead before giving up on a hostname entirely.
        return mdns_reverse_lookup(ip, timeout=mdns_timeout)


def probe_host(ip: str, ports: Iterable[int], timeout: float) -> Optional[int]:
    """Try connecting to each of the given TCP ports on ip, in order.

    Uses an ordinary client TCP socket - the only kind of socket a
    sandboxed app is allowed to open - so this works without root,
    subprocess access, or raw sockets.

    Args:
        ip: The target host's IPv4 address.
        ports: TCP ports to try, in order. Stops at the first success.
        timeout: Per-port connection timeout, in seconds.

    Returns:
        The first port that accepted a connection (host is up, and this
        is a hint at what service/device it might be - see
        PORT_SERVICES), or None if every port timed out or was refused.
    """
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            # connect_ex returns the connection's errno instead of raising
            # an exception, so a refused/timed-out port is just a nonzero
            # return value rather than something we need to catch.
            # 0 means the TCP handshake completed, i.e. something is
            # listening on that port and the host is reachable.
            if sock.connect_ex((ip, port)) == 0:
                return port
    return None


def _probe_tcp_port(ip: str, port: int, timeout: float) -> bool:
    """Return True if ip accepts a TCP connection on port.

    The same connect_ex-based check probe_host() uses, just for a single
    port rather than trying a list of them in order - callers here
    already parallelize across ports themselves, so there's no need for
    this to also stop early.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((ip, port)) == 0


# A home-network security hygiene check, not an exhaustive audit: ports
# commonly flagged as risky to leave exposed, with a one-line reason
# each. Checked independently of DEFAULT_PORTS/probe_host() above, which
# stops at the first open port it finds - a device with both 80 and 23
# (telnet) open would otherwise never reveal the telnet port if 80
# happened to be checked first.
RISKY_PORTS: Dict[int, str] = {
    21: "FTP transmits credentials in plaintext",
    23: "Telnet transmits everything, including credentials, in plaintext",
    445: "SMB is a common ransomware/worm vector when exposed beyond the LAN",
    3389: "RDP is frequently targeted by credential-stuffing and brute-force scans",
    5900: "VNC often runs with weak or no authentication by default",
}


def _find_risky_ports(ip: str, timeout: float) -> List[int]:
    """Check ip for any of RISKY_PORTS, regardless of what probe_host() found.

    Args:
        ip: The target host's IPv4 address.
        timeout: Per-port connection timeout, in seconds.

    Returns:
        Open ports from RISKY_PORTS, sorted numerically. Empty if none
        of them are open (the common, unremarkable case).
    """
    open_risky = []
    with ThreadPoolExecutor(max_workers=len(RISKY_PORTS)) as executor:
        futures = {executor.submit(_probe_tcp_port, ip, port, timeout): port for port in RISKY_PORTS}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_risky.append(port)
    return sorted(open_risky)


def _attach_risky_ports(devices: List[Device], timeout: float) -> List[Device]:
    """Fill in each device's "risky_ports" via _find_risky_ports(), in parallel, in place."""
    with ThreadPoolExecutor(max_workers=max(1, len(devices))) as executor:
        futures = {executor.submit(_find_risky_ports, d["ip"], timeout): d for d in devices}
        for future in as_completed(futures):
            futures[future]["risky_ports"] = future.result()
    return devices


def _summarize_banner(data: bytes) -> str:
    """Reduce raw banner bytes to one short, printable line.

    Args:
        data: Whatever bytes grab_banner() read back from a socket -
            could be a multi-line HTTP response, a single-line SSH
            version string, or anything else a service sends unprompted.

    Returns:
        The first non-blank line, unless a later line starts with
        "Server:" (an HTTP header worth surfacing alongside whatever
        line - usually the HTTP status line - came first), in which case
        both are joined. "" if data has no printable content at all.
    """
    text = data.decode("utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    for line in lines:
        if line.lower().startswith("server:"):
            return line if line == lines[0] else f"{lines[0]}  |  {line}"
    return lines[0][:120]


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Try to read a service banner from an already-open TCP port.

    Some protocols (SSH, FTP, and others) send a startup banner the
    moment a client connects, with no request needed. Others (HTTP) wait
    for a request first. And a fair number of IoT admin UIs run a plain
    HTTP server on some arbitrary, unrecognized port. To cover all three
    without guessing wrong, this: sends an HTTP request outright for
    ports known to speak HTTP(S); otherwise listens briefly for an
    unprompted banner, and only sends an HTTP HEAD request as a fallback
    if nothing arrived on its own.

    Args:
        ip: The target host's IPv4 address.
        port: The TCP port to grab a banner from - assumed to already be
            open (e.g. from probe_host()); this doesn't itself check.
        timeout: How long to wait for the connection and each read, in
            seconds.

    Returns:
        A short, one-line summary of whatever banner was found (see
        _summarize_banner()), or "" if the connection failed or nothing
        useful came back.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(timeout)
            raw_sock.connect((ip, port))

            if port in _HTTPS_PORTS:
                # verify_mode=CERT_NONE (with check_hostname off, which
                # CERT_NONE requires) is intentional here: this is a banner
                # grab against an arbitrary LAN device, most of which use
                # self-signed certs anyway - not a connection we need to
                # trust, just read a response from. The public
                # create_default_context() API is used (rather than the
                # private _create_unverified_context() helper) even though
                # both end up equally unverified.
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(raw_sock, server_hostname=ip)
            else:
                sock = raw_sock

            http_request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode("ascii", errors="replace")

            if port in _HTTP_PORTS or port in _HTTPS_PORTS:
                sock.sendall(http_request)
                data = sock.recv(1024)
            else:
                # Unrecognized port: listen first, since some protocols
                # (SSH, FTP) volunteer a banner with no request needed and
                # would just ignore/reject an HTTP request sent at them.
                try:
                    data = sock.recv(1024)
                except socket.timeout:
                    data = b""
                if not data:
                    # Nothing came back unprompted - try treating it as an
                    # HTTP server anyway, since plenty of IoT admin UIs run
                    # HTTP on non-standard ports.
                    sock.sendall(http_request)
                    data = sock.recv(1024)
    except (OSError, ssl.SSLError):
        return ""

    return _summarize_banner(data)


def tcp_scan(
    subnet: str,
    timeout: float = 0.5,
    ports: Sequence[int] = DEFAULT_PORTS,
    max_workers: int = 100,
    mdns_timeout: float = 0.3,
    grab_banners: bool = True,
    check_risky_ports: bool = True,
    excluded_networks: Sequence["ipaddress._BaseNetwork"] = (),
    retries: int = 0,
) -> List[Device]:
    """Discover devices by probing common TCP ports across every host in subnet.

    Args:
        subnet: CIDR range to scan, e.g. "192.168.1.0/24".
        timeout: Per-port connection timeout, in seconds. Lower values
            scan faster but may miss slow-to-respond devices. Also used
            for the banner-grab and risky-ports steps below.
        ports: TCP ports to probe on each host (see DEFAULT_PORTS).
        max_workers: How many hosts to probe (and later, resolve
            hostnames for) concurrently. A /24 subnet has 254 usable
            addresses, so doing this one at a time would take 254x as
            long as the timeout; a thread pool lets us do them all in
            parallel instead.
        mdns_timeout: How long to wait for an mDNS/Bonjour response when
            a device has no reverse-DNS hostname (see
            mdns_reverse_lookup()). Kept separate from timeout since it's
            a different, typically slower, kind of lookup.
        grab_banners: Whether to also read a banner from each device's
            open port (see grab_banner()). On by default - it's the same
            plain-socket primitives this script already uses, and often
            identifies a device that has no hostname at all - but can be
            turned off for a faster scan.
        check_risky_ports: Whether to also check each device for
            RISKY_PORTS (see _attach_risky_ports()), independently of
            whatever `ports` found - a device with both 80 and 23
            (telnet) open would otherwise never reveal the telnet port
            if 80 happened to be checked first. On by default; turn off
            for a faster scan.
        excluded_networks: Hosts matching one of these (see
            _parse_exclusions()) are dropped before any probing at all -
            no TCP connection is ever attempted against them, unlike
            network_scanner.py's ARP-broadcast case, since this script
            already probes each host individually.
        retries: Extra probe passes for hosts that didn't answer on any
            earlier pass, to recover a device that missed one connection
            attempt due to transient Wi-Fi/network flakiness rather than
            actually being offline. Unlike network_scanner.py's scan()
            (which re-broadcasts to the whole subnet, since ARP has no
            per-host equivalent), each retry here only re-probes the
            hosts still missing a match - already-found hosts aren't
            re-probed, since this script talks to each host individually
            rather than in one subnet-wide broadcast. 0 (the default)
            preserves the original single-pass behavior exactly.

    Returns:
        Discovered devices sorted by IP address, each with "hostname"
        populated from Cast service discovery (for Chromecast-port
        devices), reverse DNS, or mDNS reverse lookup - whichever found
        one first, or "" if none did - "port" set to whichever probed
        port answered first, "banner" set to whatever grab_banner() read
        from that port, or "" if grab_banners is False or nothing useful
        came back, and "risky_ports" set to whatever _find_risky_ports()
        found, or [] if check_risky_ports is False or none are open.
    """
    # strict=False: subnet may be given as a host address (e.g. from
    # get_local_subnet()) rather than a "clean" network address.
    network = ipaddress.ip_network(subnet, strict=False)
    # .hosts() excludes the network and broadcast addresses, since those
    # aren't assignable to real devices.
    hosts = list(network.hosts())
    if excluded_networks:
        hosts = [ip for ip in hosts if not _is_excluded(str(ip), excluded_networks)]

    # Maps each live host to the port that answered, so tcp_scan() can
    # report it alongside the hostname - a useful fingerprint for devices
    # with no reverse-DNS name (see PORT_SERVICES).
    matched_ports: Dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit every probe up front; futures maps each pending result
        # back to the IP it's checking, since as_completed() only hands
        # back the future itself, not its arguments.
        futures = {executor.submit(probe_host, str(ip), ports, timeout): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            port = future.result()
            if port is not None:
                matched_ports[str(ip)] = port

    # Only re-probes hosts still missing a match, not everyone again -
    # each pass here is an independent TCP connect per host rather than
    # one subnet-wide broadcast, so there's no reason to pay the timeout
    # twice for a host that already answered.
    for _ in range(retries):
        still_missing = [ip for ip in hosts if str(ip) not in matched_ports]
        if not still_missing:
            break
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(probe_host, str(ip), ports, timeout): ip for ip in still_missing}
            for future in as_completed(futures):
                ip = futures[future]
                port = future.result()
                if port is not None:
                    matched_ports[str(ip)] = port

    # Chromecasts (and other Google Cast devices) generally don't answer
    # mdns_reverse_lookup()'s reverse-PTR question - that's an optional
    # part of the mDNS spec, and Google's Cast stack doesn't implement
    # it - but they always answer DNS-SD's "who offers this service?"
    # question, since that's the actual mechanism every casting app uses
    # to find them. Only bother asking if a Cast-looking device actually
    # showed up: it's one extra mdns_timeout-long wait regardless of how
    # many devices are on the subnet, so it's not worth paying when
    # nothing here looks like a Cast device anyway.
    cast_names: Dict[str, str] = {}
    if any(port == _CAST_CONTROL_PORT for port in matched_ports.values()):
        cast_names = mdns_service_lookup(_CAST_SERVICE_TYPE, timeout=mdns_timeout)

    # Grabbing a banner from every live host's open port up front (rather
    # than only when printing) keeps this the one place tcp_scan() talks
    # to each device, same as the hostname-resolution step below - and a
    # thread pool again avoids paying each grab_banner() timeout serially.
    banners: Dict[str, str] = {}
    if grab_banners and matched_ports:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(grab_banner, ip_str, port, timeout): ip_str
                for ip_str, port in matched_ports.items()
            }
            for future in as_completed(futures):
                ip_str = futures[future]
                banners[ip_str] = future.result()

    devices: List[Device] = []
    # IPs Cast service discovery already named don't need the slower,
    # per-host reverse-DNS/mDNS fallback below.
    remaining_ips = [ip_str for ip_str in matched_ports if ip_str not in cast_names]

    # Resolving hostnames one at a time would add up fast once mDNS is
    # involved: a device that doesn't support it costs a full
    # mdns_timeout wait, and on a subnet with several such devices that's
    # additive if done sequentially. A thread pool runs them all at once
    # instead, same as the port-probing step above.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_resolve_hostname, ip_str, mdns_timeout): ip_str for ip_str in remaining_ips
        }
        for future in as_completed(futures):
            ip_str = futures[future]
            hostname = future.result()
            devices.append(
                {
                    "ip": ip_str,
                    "hostname": hostname,
                    "port": matched_ports[ip_str],
                    "banner": banners.get(ip_str, ""),
                    "risky_ports": [],
                }
            )

    for ip_str, hostname in cast_names.items():
        if ip_str in matched_ports:
            devices.append(
                {
                    "ip": ip_str,
                    "hostname": hostname,
                    "port": matched_ports[ip_str],
                    "banner": banners.get(ip_str, ""),
                    "risky_ports": [],
                }
            )

    if check_risky_ports and devices:
        # Runs over the final device list rather than per-port like the
        # banner grab above, since RISKY_PORTS is a fixed, small set
        # checked the same way regardless of which port matched_ports
        # found for a given host.
        devices = _attach_risky_ports(devices, timeout)

    # Sort numerically by IP (not lexicographically as strings, which would
    # put "10.0.0.2" after "10.0.0.10").
    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


def scan_all_subnets(
    subnets: Iterable[str],
    timeout: float = 0.5,
    ports: Sequence[int] = DEFAULT_PORTS,
    max_workers: int = 100,
    mdns_timeout: float = 0.3,
    grab_banners: bool = True,
    check_risky_ports: bool = True,
    excluded_networks: Sequence["ipaddress._BaseNetwork"] = (),
    retries: int = 0,
) -> List[Device]:
    """Run tcp_scan() over multiple subnets and merge the results into one list.

    Args:
        subnets: CIDR ranges to scan, e.g. ["192.168.1.0/24", "10.0.0.0/24"].
        timeout: Passed through to tcp_scan() for each subnet.
        ports: Passed through to tcp_scan() for each subnet.
        max_workers: Passed through to tcp_scan() for each subnet.
        mdns_timeout: Passed through to tcp_scan() for each subnet.
        grab_banners: Passed through to tcp_scan() for each subnet.
        check_risky_ports: Passed through to tcp_scan() for each subnet.
        excluded_networks: Passed through to tcp_scan() for each subnet.
        retries: Passed through to tcp_scan() for each subnet.

    Returns:
        Every discovered device across all subnets, sorted by IP and
        de-duplicated by IP address (the same device could otherwise be
        listed twice if two of the given subnets overlap).
    """
    # Keyed by IP so a later subnet's result for the same address simply
    # overwrites the earlier one rather than producing a duplicate row.
    devices_by_ip: Dict[str, Device] = {}
    for subnet in subnets:
        for device in tcp_scan(
            subnet,
            timeout=timeout,
            ports=ports,
            max_workers=max_workers,
            mdns_timeout=mdns_timeout,
            grab_banners=grab_banners,
            check_risky_ports=check_risky_ports,
            excluded_networks=excluded_networks,
            retries=retries,
        ):
            devices_by_ip[device["ip"]] = device

    return sorted(devices_by_ip.values(), key=lambda d: ipaddress.ip_address(d["ip"]))


# --- Known-device tracking, for flagging newly-seen devices ---

# A small local registry of every device this script has ever seen,
# persisted between runs so a scan can tell "this device wasn't here
# last time" apart from "this device is always here".
_KNOWN_DEVICES_PATH = Path.home() / ".cache" / "mobile_network_scanner_known_devices.json"


def _device_identity(device: Device) -> str:
    """Return the key used to recognize a device across scans.

    Unlike network_scanner.py, this script never has a MAC address to
    key on (TCP port probing reveals nothing below the IP layer), so a
    device's IP is the only identifier available - meaning a DHCP lease
    change will make a device look "new" again even though it isn't.
    """
    return device["ip"]


def _load_known_devices(path: Path) -> Dict[str, dict]:
    """Load the known-devices registry from disk.

    Returns:
        The registry (a dict keyed by _device_identity()), or {} if the
        file doesn't exist yet (first run) or is unreadable/corrupt.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_known_devices(known: Dict[str, dict], path: Path) -> None:
    """Persist the known-devices registry to disk.

    Failing to save (read-only filesystem, out of disk space, etc.)
    deliberately doesn't raise - the NEW/known markers for the scan that
    just ran are already correct in memory either way, so losing the
    ability to remember them for *next* time shouldn't crash this run.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(known, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        pass


def _mark_new_devices(devices: List[Device], known_devices_path: Path = _KNOWN_DEVICES_PATH) -> Dict[str, bool]:
    """Compare devices against the known-devices registry, updating it on disk.

    Args:
        devices: This scan's results.
        known_devices_path: Where the registry is stored between runs
            (overridable for tests; production code should just use the
            default).

    Returns:
        A dict mapping each device's _device_identity() to True if this
        is the first time it's ever been seen, or False if it was
        already in the registry from a previous run.
    """
    known = _load_known_devices(known_devices_path)
    now = datetime.now().isoformat(timespec="seconds")

    is_new: Dict[str, bool] = {}
    for device in devices:
        key = _device_identity(device)
        is_new[key] = key not in known
        entry = known.setdefault(key, {"first_seen": now})
        entry["last_seen"] = now
        entry["port"] = device.get("port")
        entry["hostname"] = device.get("hostname", "")

    _save_known_devices(known, known_devices_path)
    return is_new


def _find_port_changes(
    devices: List[Device], known_devices_path: Path = _KNOWN_DEVICES_PATH
) -> Dict[str, Tuple[Optional[int], int]]:
    """Compare each device's current port against what the registry last recorded.

    Must be called *before* _mark_new_devices() overwrites the registry
    with this scan's port - otherwise the "previous" value is already
    gone by the time this reads it. A changed port is a signal worth
    surfacing on its own, distinct from RISKY_PORTS: a device that starts
    answering on a different port than before is worth a second look
    even when that port isn't on the risky list, and this needs no new
    probing at all - just diffing data _mark_new_devices() already
    persists.

    Args:
        devices: This scan's results.
        known_devices_path: Where the registry is stored between runs
            (overridable for tests; production code should just use the
            default).

    Returns:
        A dict mapping each changed device's _device_identity() to
        (previous_port, current_port). Only devices already in the
        registry are considered - a device seeing its first-ever port
        isn't a "change", it's just NEW (see _mark_new_devices()).
    """
    known = _load_known_devices(known_devices_path)

    changes: Dict[str, Tuple[Optional[int], int]] = {}
    for device in devices:
        key = _device_identity(device)
        entry = known.get(key)
        if entry is None:
            continue
        previous_port = entry.get("port")
        current_port = device["port"]
        if previous_port != current_port:
            changes[key] = (previous_port, current_port)

    return changes


def _find_missing_devices(devices: List[Device], known_devices_path: Path = _KNOWN_DEVICES_PATH) -> List[dict]:
    """Find registry entries for devices that didn't show up in this scan.

    The inverse of _mark_new_devices(): instead of flagging what's newly
    *present*, this reports what's newly *absent* - a device seen in some
    previous scan but missing from this one (asleep, out of range, powered
    off, etc.). The registry itself is never pruned here - a device just
    stops appearing in this list again once a later scan finds it.

    Args:
        devices: This scan's results.
        known_devices_path: Where the registry is stored between runs
            (overridable for tests; production code should just use the
            default).

    Returns:
        Registry entries (each augmented with its identity key under
        "key") for every known device absent from devices, sorted by
        that key for stable output.
    """
    known = _load_known_devices(known_devices_path)
    current_keys = {_device_identity(device) for device in devices}

    missing = [dict(entry, key=key) for key, entry in known.items() if key not in current_keys]
    return sorted(missing, key=lambda entry: entry["key"])


# --- Exclusion filtering (--exclude) ---
#
# Skip specific hosts from being probed at all - a fragile device that
# crashes under port probes, or one you don't want woken from sleep -
# without narrowing the whole subnet just to dodge one host.

def _parse_exclusions(spec: str) -> List["ipaddress._BaseNetwork"]:
    """Parse --exclude's comma-separated IP/CIDR list into networks.

    Args:
        spec: e.g. "192.168.1.50,192.168.1.64/28".

    Returns:
        One network per entry. A bare IP (no "/") is treated as a /32 -
        excluding just that one address - so CIDR notation is only
        needed for an actual range.

    Raises:
        ValueError: an entry isn't a valid IP or CIDR range.
    """
    networks = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" not in part:
            part = f"{part}/32"
        networks.append(ipaddress.ip_network(part, strict=False))
    return networks


def _is_excluded(ip: str, excluded_networks: Sequence["ipaddress._BaseNetwork"]) -> bool:
    """Return True if ip falls inside any of excluded_networks."""
    address = ipaddress.ip_address(ip)
    return any(address in network for network in excluded_networks)


# --- Custom device labels/aliases ---
#
# A friendly name (e.g. "Kitchen Echo") for a device whose real hostname is
# cryptic or blank, stored in the same known-devices registry as
# first_seen/last_seen - not a separate file, so there's only one place
# tracking what this script knows about a given device.

def _set_label(key: str, label: str, known_devices_path: Path = _KNOWN_DEVICES_PATH) -> None:
    """Assign a custom label to a device, in the known-devices registry.

    Args:
        key: The device's _device_identity() - its IP address (this
            script has no MAC to key on - see _device_identity()).
        label: The friendly name to show instead of/alongside its
            hostname (see _display_hostname()).
        known_devices_path: Where the registry is stored between runs
            (overridable for tests; production code should just use the
            default).

    A device doesn't need to already be in the registry - this creates a
    minimal entry if needed, so a label can be set for a device right
    after seeing its IP in a previous scan's output, without waiting for
    it to show up again. One side effect: that minimal entry means the
    device won't be flagged NEW next time it's actually scanned, since
    _mark_new_devices() only checks whether the key is already present,
    not whether it came from a real scan or a label.
    """
    known = _load_known_devices(known_devices_path)
    entry = known.setdefault(key, {})
    entry["label"] = label
    _save_known_devices(known, known_devices_path)


def _remove_label(key: str, known_devices_path: Path = _KNOWN_DEVICES_PATH) -> None:
    """Remove a device's custom label, if any, leaving the rest of its registry entry intact."""
    known = _load_known_devices(known_devices_path)
    if "label" in known.get(key, {}):
        del known[key]["label"]
        _save_known_devices(known, known_devices_path)


def _load_labels(known_devices_path: Path = _KNOWN_DEVICES_PATH) -> Dict[str, str]:
    """Load every device's custom label (see _set_label()) from the registry.

    Returns:
        A dict mapping each labeled device's _device_identity() to its
        label. Devices without one set are omitted entirely (not mapped
        to "").
    """
    known = _load_known_devices(known_devices_path)
    return {key: entry["label"] for key, entry in known.items() if entry.get("label")}


def _display_hostname(hostname: str, label: str) -> str:
    """Combine a device's real hostname with its custom label, if any.

    Args:
        hostname: The device's actual hostname from this scan, or "" if
            none was found.
        label: Its custom label from _load_labels(), or "" if none is set.

    Returns:
        "label (hostname)" if both are set and differ (so neither is
        lost), just the label if hostname is blank or identical to it,
        or the bare hostname if there's no label at all.
    """
    if label and hostname and label != hostname:
        return f"{label} ({hostname})"
    return label or hostname


# --- Colorized terminal output ---
#
# Plain ANSI escape codes, not a library like colorama - a-Shell's
# terminal (and any other terminal worth colorizing) already understands
# these natively.

_ANSI_CODES: Dict[str, str] = {
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def _use_color(no_color_flag: bool) -> bool:
    """Decide whether to emit ANSI color codes at all.

    Color is skipped if the user passed --no-color, if the NO_COLOR
    environment variable is set (https://no-color.org - a convention
    respected by a wide range of CLI tools), or if stdout isn't
    connected to a terminal at all (piped to a file or another program,
    where raw escape codes would just be noise mixed into the output).

    Args:
        no_color_flag: The --no-color CLI flag's value.

    Returns:
        True if it's safe and wanted to emit color codes.
    """
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _colorize(text: str, color: str, enabled: bool) -> str:
    """Wrap text in an ANSI color code, or return it unchanged if enabled is False."""
    if not enabled:
        return text
    return f"{_ANSI_CODES[color]}{text}{_ANSI_CODES['reset']}"


# --- Exporting results to CSV/JSON ---

# Columns written by --output, in order for CSV (JSON uses these same keys
# but isn't column-ordered).
_EXPORT_FIELDS: Tuple[str, ...] = ("ip", "hostname", "port", "banner", "risky_ports")


def _export_json(devices: List[Device], path: Path) -> None:
    """Write devices to path as a JSON array, one object per device."""
    path.write_text(json.dumps(devices, indent=2), encoding="utf-8")


def _export_csv(devices: List[Device], path: Path, fieldnames: Sequence[str]) -> None:
    """Write devices to path as CSV, one row per device.

    A list value (risky_ports) is flattened to a ";"-separated string,
    since a CSV cell can't hold a real list.
    """
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for device in devices:
            row = {}
            for key in fieldnames:
                value = device.get(key)
                if isinstance(value, list):
                    value = ";".join(str(item) for item in value)
                row[key] = "" if value is None else value
            writer.writerow(row)


def export_results(devices: List[Device], path: Path, fieldnames: Sequence[str] = _EXPORT_FIELDS) -> None:
    """Save this scan's results to path, independent of the known-devices registry.

    Args:
        devices: This scan's results, exactly as printed in the results table.
        path: Where to write. Format is chosen by the extension: ".csv"
            writes CSV, anything else (typically ".json") writes JSON.
        fieldnames: Which Device keys to include, and in what order for CSV.
    """
    if path.suffix.lower() == ".csv":
        _export_csv(devices, path, fieldnames)
    else:
        _export_json(devices, path)


# --- Scan history log ---
#
# A separate concern from the known-devices registry: that registry only
# ever holds first_seen/last_seen (the earliest and most recent sighting),
# so "was this device here at 3pm yesterday" isn't answerable from it -
# only every scan's own full snapshot, kept over time, can answer that.

_DEFAULT_HISTORY_MAX_ENTRIES = 200


def _trim_scan_history(path: Path, max_entries: int) -> None:
    """Drop the oldest lines from path's history log once it exceeds max_entries.

    Reads the whole file back to trim it - fine for the sizes this is
    meant for (a few hundred scans' worth of JSON lines), and simpler
    than maintaining a ring buffer on disk. Only rewrites when actually
    over the cap, so a normal append_scan_history() call is just the one
    cheap append, not a read-modify-write every time.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    if len(lines) <= max_entries:
        return
    try:
        path.write_text("\n".join(lines[-max_entries:]) + "\n", encoding="utf-8")
    except OSError:
        pass


def append_scan_history(
    devices: List[Device], path: Path, max_entries: int = _DEFAULT_HISTORY_MAX_ENTRIES
) -> None:
    """Append this scan's results to a rolling history log at path.

    One JSON object per line (JSON Lines, not a single JSON array), so
    appending a new scan never requires reading or rewriting the whole
    file except when trimming old entries.

    Args:
        devices: This scan's results, exactly as printed/exported -
            logged even if empty, since "nothing was here at this
            timestamp" is itself part of the history.
        path: Where the history log is stored.
        max_entries: How many scans to keep before dropping the oldest.

    Failing to write (read-only filesystem, out of disk space, etc.)
    deliberately doesn't raise - the same rule _save_known_devices()
    follows, since losing the history log shouldn't crash the scan that
    triggered it.
    """
    entry = json.dumps({"timestamp": datetime.now().isoformat(timespec="seconds"), "devices": devices})
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except OSError:
        return

    _trim_scan_history(path, max_entries)


# --- Notifications for --watch (or any run with something to report) ---

def _build_notification_message(
    devices: List[Device],
    is_new: Dict[str, bool],
    port_changes: Dict[str, Tuple[Optional[int], int]],
    missing: List[dict],
    risky_devices: List[Device],
) -> str:
    """Build a plain-text summary of one scan's NEW/CHG/missing/risky findings.

    Same content as the results table's own summary sections, minus the
    ANSI color codes and table alignment a webhook receiver wouldn't
    render anyway - built as its own function, independent of the print
    loop, so it can be unit-tested without capturing stdout.

    Returns:
        A multi-line summary, or "" if none of the four categories has
        anything in it - callers should treat that as "nothing to send".
    """
    def port_label(port: Optional[int]) -> str:
        return "(none)" if port is None else f"{PORT_SERVICES.get(port, '?')} ({port})"

    sections: List[str] = []

    new_devices = [d for d in devices if is_new.get(_device_identity(d))]
    if new_devices:
        lines = [f"{len(new_devices)} new device(s):"]
        for device in new_devices:
            lines.append(f"  {device['ip']}  {device.get('hostname') or '(no hostname)'}")
        sections.append("\n".join(lines))

    if port_changes:
        lines = [f"{len(port_changes)} device(s) with a changed port:"]
        for device in devices:
            key = _device_identity(device)
            if key in port_changes:
                previous_port, current_port = port_changes[key]
                lines.append(f"  {device['ip']}  {port_label(previous_port)} -> {port_label(current_port)}")
        sections.append("\n".join(lines))

    if missing:
        lines = [f"{len(missing)} previously-seen device(s) missing:"]
        for entry in missing:
            label = entry.get("label") or entry.get("hostname") or ""
            suffix = f" ({label})" if label else ""
            lines.append(f"  {entry['key']}{suffix}")
        sections.append("\n".join(lines))

    if risky_devices:
        lines = [f"{len(risky_devices)} device(s) exposing a risky port:"]
        for device in risky_devices:
            port_labels = ", ".join(f"{PORT_SERVICES.get(p, str(p))} ({p})" for p in device["risky_ports"])
            lines.append(f"  {device['ip']}  {port_labels}")
        sections.append("\n".join(lines))

    return "\n\n".join(sections)


def send_webhook_notification(url: str, message: str, timeout: float = 5.0) -> bool:
    """POST message to a webhook URL as JSON: {"text": message}.

    This is the format Slack's incoming webhooks (and many other generic
    webhook receivers) expect directly - a deliberately simple, single
    format rather than special-casing any one service's exact schema. A
    target expecting something else (Discord's "content" key, ntfy.sh's
    plain-text body) may need a small relay in between.

    Args:
        url: The webhook endpoint to POST to.
        message: The notification text (see _build_notification_message()).
        timeout: How long to wait for the request, in seconds.

    Returns:
        True if the request got back a 2xx response, False on any
        failure (network error, timeout, non-2xx status) - logged to
        stderr but never raised, so a bad or unreachable webhook doesn't
        crash the scan itself.
    """
    payload = json.dumps({"text": message}).encode("utf-8")
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"Warning: webhook notification failed: {exc}", file=sys.stderr)
        return False


# --- Environment diagnostics (--doctor) ---
#
# This script's discovery techniques are already the most restricted set
# either scanner uses (see the module docstring), so there's less to check
# than network_scanner.py has - but the mDNS limitation in particular is
# easy to only discover as "no hostname," rather than the platform
# restriction it actually is (see mdns_diagnostic.py). --doctor surfaces
# that up front, in one pass, instead.

def _check_python_version() -> Tuple[bool, str]:
    return True, f"Running Python {sys.version.split()[0]}"


def _check_local_subnet() -> Tuple[bool, str]:
    try:
        subnet = get_local_subnet()
    except OSError as exc:
        return False, f"Couldn't detect the local subnet ({exc}) - pass one explicitly instead of relying on auto-detect"
    return True, f"Detected {subnet}"


def _check_tcp_connectivity() -> Tuple[bool, str]:
    """Confirm this sandbox allows an ordinary outbound TCP connection at all.

    Uses a well-known public address (Google's DNS) purely as a target
    that's normally reachable - not a check of internet access for its
    own sake. A failure here doesn't necessarily mean LAN scanning won't
    work (a LAN with no WAN access is a legitimate setup), just that
    something more fundamental than mDNS is worth ruling out first.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2.0)
            sock.connect(("8.8.8.8", 53))
    except OSError as exc:
        return False, f"Couldn't open an outbound TCP connection ({exc}) - could be a real network problem, or just no WAN access from this LAN"
    return True, "Outbound TCP connections work"


def _check_cache_writable() -> Tuple[bool, str]:
    cache_dir = Path.home() / ".cache"
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        probe = cache_dir / ".mobile_network_scanner_doctor_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return False, f"{cache_dir} is not writable ({exc}) - known-devices tracking won't persist between runs"
    return True, f"{cache_dir} is writable"


def _check_mdns_multicast() -> Tuple[bool, str]:
    """Try the exact bind/join/send sequence mdns_reverse_lookup()/mdns_service_lookup() depend on.

    On iOS, the send is what actually fails - bind and join typically
    succeed - with OSError(65, 'No route to host'), a platform
    restriction (Apple's Local Network Privacy model) rather than
    anything fixable in this script's Python code. See the module
    docstring and mdns_diagnostic.py for the full story.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("", 5353))
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                    struct.pack("4sl", socket.inet_aton(_MDNS_GROUP[0]), socket.INADDR_ANY),
                )
            except OSError:
                pass  # Not fatal by itself - mdns_service_lookup() falls back to an ordinary socket too.
            sock.sendto(_build_mdns_ptr_query("_services._dns-sd._udp.local"), _MDNS_GROUP)
    except OSError as exc:
        return False, f"Can't send to the mDNS multicast group ({exc}) - likely iOS's Local Network Privacy restriction, not fixable here"
    return True, "Can send to the mDNS multicast group (a reply isn't guaranteed even so)"


_DOCTOR_CHECKS: Tuple[Tuple[str, object], ...] = (
    ("Python version", _check_python_version),
    ("Local subnet detection", _check_local_subnet),
    ("Outbound TCP connectivity", _check_tcp_connectivity),
    ("Cache directory", _check_cache_writable),
    ("mDNS multicast", _check_mdns_multicast),
)


def run_doctor(color: bool = False) -> bool:
    """Check this environment for everything mobile_network_scanner.py can use, and report it.

    Doesn't change any behavior - a scan runs the same with or without
    this - it just surfaces the reasoning behind a limitation you'd
    otherwise only discover mid-scan, most notably mDNS/Bonjour lookups
    silently finding nothing on iOS.

    Args:
        color: Whether to colorize each check's pass/fail marker.

    Returns:
        True if every check passed, False if at least one failed - a
        failed mDNS check in particular is an iOS platform restriction,
        not something a scan retry or a code change here can fix (see
        _check_mdns_multicast()).
    """
    print("mobile_network_scanner.py environment check\n")

    all_ok = True
    for name, check in _DOCTOR_CHECKS:
        ok, detail = check()
        all_ok = all_ok and ok
        marker = _colorize("OK  ", "green", color) if ok else _colorize("WARN", "yellow", color)
        print(f"  [{marker}] {name}: {detail}")

    print()
    if all_ok:
        print("Everything checks out.")
    else:
        print("Some checks reported a limitation - see above. Most have a fallback, so try a scan; it may work fine regardless.")
    return all_ok


# --- --diff-only watch mode: field-level diffing between consecutive ticks ---

def diff_devices(old_devices: List[Device], new_devices: List[Device]) -> Dict[str, list]:
    """Compare two device lists field-by-field - the same comparison scan_diff.py performs on two saved files.

    Duplicated here (not imported - see this project's README for why
    every script stays independently self-contained) and adapted for two
    in-memory device lists from consecutive --watch ticks instead of two
    files on disk. Devices are matched the same way this script's own
    registry-based NEW/CHG tracking already does (_device_identity()).

    Args:
        old_devices: The previous tick's scan results.
        new_devices: This tick's scan results.

    Returns:
        {"added": [...], "removed": [...], "changed": [{"key", "ip", "changes": {field: (old, new)}}]},
        sorted the same way scan_diff.py's own diff_devices() does (a
        plain string sort on "ip", not an ipaddress-aware one - kept
        consistent with the function this is modeled on rather than with
        this script's own table, which does sort IP-aware).
    """
    def normalize(device: Device) -> dict:
        out = dict(device)
        out["risky_ports"] = sorted(out.get("risky_ports") or [])
        return out

    old_by_key = {_device_identity(d): normalize(d) for d in old_devices}
    new_by_key = {_device_identity(d): normalize(d) for d in new_devices}

    added = [new_by_key[key] for key in new_by_key if key not in old_by_key]
    removed = [old_by_key[key] for key in old_by_key if key not in new_by_key]

    changed = []
    for key in sorted(set(old_by_key) & set(new_by_key)):
        old_device, new_device = old_by_key[key], new_by_key[key]
        # "ip" is excluded here since it's shown as this entry's own
        # label already, not itemized as a field-level change.
        fields = sorted((set(old_device) | set(new_device)) - {"ip"})
        changes = {
            field: (old_device.get(field), new_device.get(field))
            for field in fields
            if old_device.get(field) != new_device.get(field)
        }
        if changes:
            changed.append({"key": key, "ip": new_device.get("ip", old_device.get("ip")), "changes": changes})

    return {
        "added": sorted(added, key=lambda d: d["ip"]),
        "removed": sorted(removed, key=lambda d: d["ip"]),
        "changed": changed,
    }


def _print_diff_only(diff: Dict[str, list], color: bool) -> None:
    """Print just a --diff-only tick's changes (added/removed/changed devices) instead of the full results table."""
    if not diff["added"] and not diff["removed"] and not diff["changed"]:
        print("No changes since the last tick.")
        return
    if diff["added"]:
        print(_colorize(f"{len(diff['added'])} device(s) added:", "green", color))
        for device in diff["added"]:
            print(_colorize(f"  {device['ip']:<20}{device.get('hostname') or ''}", "green", color))
    if diff["removed"]:
        print(_colorize(f"{len(diff['removed'])} device(s) removed:", "dim", color))
        for device in diff["removed"]:
            print(_colorize(f"  {device['ip']:<20}{device.get('hostname') or ''}", "dim", color))
    if diff["changed"]:
        print(_colorize(f"{len(diff['changed'])} device(s) changed:", "yellow", color))
        for entry in diff["changed"]:
            print(_colorize(f"  {entry['ip']}", "yellow", color))
            for field, (old_value, new_value) in entry["changes"].items():
                print(_colorize(f"    {field}: {old_value} -> {new_value}", "yellow", color))


# --- Config file / profiles ---

_DEFAULT_PROFILE_PATH = Path.home() / ".mobile_network_scanner.ini"


def _load_profile(name: str, path: Path) -> Dict[str, str]:
    """Load one named [section] from an INI-format profile file as a dict of raw string values.

    Returns:
        {} if the file doesn't exist, isn't valid INI, or has no section
        by this name - callers treat that the same as "no profile", not
        as an error, except main() itself, which does treat an
        explicitly-requested --profile name not existing as a usage error.
    """
    config = configparser.ConfigParser()
    try:
        read_ok = config.read(path)
    except configparser.Error:
        return {}
    if not read_ok or not config.has_section(name):
        return {}
    return dict(config.items(name))


def _apply_profile(parser: argparse.ArgumentParser, profile: Dict[str, str]) -> None:
    """Coerce a profile's raw string values using each flag's own declared type, then install them as new parser defaults.

    This is the single source of truth this project's own TODO called
    for when this feature was first proposed: rather than maintaining a
    second, separately-tracked schema of "what's configurable and what
    type is it", this reads that straight back out of the parser's own
    already-declared arguments (via its `_actions` list - a stable, if
    technically private, argparse attribute long relied on in the wild
    for exactly this kind of introspection). A profile key that doesn't
    match any flag (e.g. one written for an older version of this script,
    before a flag was renamed) is silently ignored rather than erroring.
    A repeatable flag (--set-label, --remove-label; action="append") is
    also skipped - a profile can't meaningfully seed a growing list this
    way, so it's left at its own empty-list default instead of being
    silently replaced by one raw string.

    Explicit CLI flags still win: set_defaults() only changes what
    parse_args() falls back to when a flag isn't given on the command
    line at all.
    """
    dest_to_action = {action.dest: action for action in parser._actions if action.dest and action.dest != argparse.SUPPRESS}

    coerced: Dict[str, object] = {}
    for key, raw_value in profile.items():
        dest = key.replace("-", "_")
        action = dest_to_action.get(dest)
        if action is None or isinstance(action, argparse._AppendAction):
            continue
        if isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
            coerced[dest] = raw_value.strip().lower() in ("1", "true", "yes", "on")
        elif action.type is not None:
            coerced[dest] = action.type(raw_value)
        else:
            coerced[dest] = raw_value

    parser.set_defaults(**coerced)


# --- Prometheus textfile export ---

def render_prometheus_metrics(device_count: int, new_count: int, risky_count: int, timestamp: float) -> str:
    """Render this scan's summary counts in Prometheus text exposition format, for node_exporter's textfile collector.

    No IP-conflict metric here, unlike network_scanner.py's own version
    of this function: this script has no MAC to compare against at all
    (see _device_identity()'s own docstring), so there's no equivalent
    check to report a count for.

    Args:
        timestamp: Unix timestamp of this scan, typically time.time().

    Returns:
        Complete file content, each metric preceded by its own HELP/TYPE
        comment lines per the exposition format - ready to write as-is.
    """
    lines = [
        "# HELP mobile_network_scanner_devices_total Devices found in the most recent scan.",
        "# TYPE mobile_network_scanner_devices_total gauge",
        f"mobile_network_scanner_devices_total {device_count}",
        "# HELP mobile_network_scanner_devices_new_total Newly-seen devices in the most recent scan.",
        "# TYPE mobile_network_scanner_devices_new_total gauge",
        f"mobile_network_scanner_devices_new_total {new_count}",
        "# HELP mobile_network_scanner_devices_risky_total Devices exposing a risky port in the most recent scan.",
        "# TYPE mobile_network_scanner_devices_risky_total gauge",
        f"mobile_network_scanner_devices_risky_total {risky_count}",
        "# HELP mobile_network_scanner_last_scan_timestamp_seconds Unix timestamp of the most recent scan.",
        "# TYPE mobile_network_scanner_last_scan_timestamp_seconds gauge",
        f"mobile_network_scanner_last_scan_timestamp_seconds {timestamp}",
    ]
    return "\n".join(lines) + "\n"


def write_prometheus_metrics(path: Path, device_count: int, new_count: int, risky_count: int, timestamp: float) -> None:
    """Write render_prometheus_metrics()'s output to path, atomically.

    Writes to a temporary file in the same directory first, then
    os.replace()s it into place - node_exporter's textfile collector
    polls this directory on its own schedule, independent of this
    script's own run, and would otherwise have a real chance of reading a
    half-written file mid-write. A failed write (unwritable directory,
    full disk) is swallowed, the same convention every other export/log
    flag in this script already follows.
    """
    content = render_prometheus_metrics(device_count, new_count, risky_count, timestamp)
    tmp_path = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.write_text(content, encoding="utf-8")
        os.replace(tmp_path, path)
    except OSError:
        pass


# --- Known-devices registry export/import ---

def export_known_devices(path: Path, known_devices_path: Path = _KNOWN_DEVICES_PATH) -> int:
    """Copy the known-devices registry to path, for backing it up or moving it to a new machine.

    It's already a plain, portable JSON file - see this project's own
    TODO note that a dedicated export format probably wasn't needed - so
    this is little more than a documented, discoverable copy. Written the
    same way _save_known_devices() writes the registry itself
    (indent=2, sort_keys=True), so the exported file is diff-friendly too.

    Returns:
        The number of entries exported.
    """
    known = _load_known_devices(known_devices_path)
    path.write_text(json.dumps(known, indent=2, sort_keys=True), encoding="utf-8")
    return len(known)


def import_known_devices(path: Path, known_devices_path: Path = _KNOWN_DEVICES_PATH) -> int:
    """Merge path's registry entries into the current known-devices registry.

    Imported entries take precedence on a key collision - a deliberate
    "restore from backup" semantic, not a symmetric merge - so importing
    onto an empty registry (a fresh machine) is a full restore, and
    importing onto one that already has some entries still lets the
    backup win for anything both sides know about.

    Returns:
        The number of entries imported (0 if path has none, or doesn't
        parse as a known-devices registry at all - see _load_known_devices()).
    """
    incoming = _load_known_devices(path)
    if not incoming:
        return 0
    current = _load_known_devices(known_devices_path)
    current.update(incoming)
    _save_known_devices(current, known_devices_path)
    return len(incoming)


# --- MQTT / Home Assistant presence publishing ---
#
# A from-scratch, publish-only MQTT 3.1.1 client over a plain TCP socket
# (stdlib only) - the same "implement the wire protocol yourself rather
# than add a dependency" approach this project already takes for DHCP
# (dhcp_monitor.py), DNS (dns_check.py), and UPnP/SOAP (upnp_audit.py).
# Publish-only: there's no subscribe/receive path at all, since a
# presence sensor only ever pushes its own state, and staying at QoS 0
# (fire-and-forget) needs no packet-identifier bookkeeping or ack
# handling to implement - an acceptable trade for a value that's about
# to be republished again next scan anyway.

_MQTT_TOPIC_SAFE_PATTERN = re.compile(r"[^a-zA-Z0-9_-]")


def _mqtt_encode_remaining_length(length: int) -> bytes:
    """Encode an MQTT fixed-header "remaining length" field: a base-128 varint, up to 4 bytes (max 268435455)."""
    if length < 0 or length > 268435455:
        raise ValueError(f"MQTT remaining length out of range: {length}")
    encoded = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length > 0:
            byte |= 0x80
        encoded.append(byte)
        if length == 0:
            break
    return bytes(encoded)


def _mqtt_encode_string(value: str) -> bytes:
    """Encode an MQTT "UTF-8 string" field: a 2-byte big-endian length prefix followed by the encoded bytes."""
    data = value.encode("utf-8")
    return struct.pack(">H", len(data)) + data


def _mqtt_connect_packet(
    client_id: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    keepalive: int = 60,
    will_topic: Optional[str] = None,
    will_payload: bytes = b"",
    will_retain: bool = False,
) -> bytes:
    """Build an MQTT CONNECT packet (protocol level 4, i.e. MQTT 3.1.1), clean-session.

    A Will Message (will_topic/will_payload/will_retain) is the broker's
    own job to deliver, not ours: it's published automatically if this
    connection drops without a clean DISCONNECT (a crash, a killed
    process, lost power) - see publish_mqtt()'s availability_topic for
    the actual use of this. Always QoS 0, matching every other publish
    this client sends - no Will QoS bits are ever set.
    """
    protocol_name = _mqtt_encode_string("MQTT")
    protocol_level = bytes([4])
    connect_flags = 0x02  # Clean Session
    if will_topic is not None:
        connect_flags |= 0x04  # Will Flag
        if will_retain:
            connect_flags |= 0x20  # Will Retain
    if username is not None:
        connect_flags |= 0x80
    if password is not None:
        connect_flags |= 0x40
    variable_header = protocol_name + protocol_level + bytes([connect_flags]) + struct.pack(">H", keepalive)
    payload = _mqtt_encode_string(client_id)
    if will_topic is not None:
        payload += _mqtt_encode_string(will_topic)
        payload += struct.pack(">H", len(will_payload)) + will_payload
    if username is not None:
        payload += _mqtt_encode_string(username)
    if password is not None:
        payload += _mqtt_encode_string(password)
    body = variable_header + payload
    return bytes([0x10]) + _mqtt_encode_remaining_length(len(body)) + body


def _mqtt_publish_packet(topic: str, payload: bytes, retain: bool = False) -> bytes:
    """Build an MQTT PUBLISH packet at QoS 0."""
    flags = 0x30 | (0x01 if retain else 0x00)
    body = _mqtt_encode_string(topic) + payload
    return bytes([flags]) + _mqtt_encode_remaining_length(len(body)) + body


_MQTT_DISCONNECT_PACKET = bytes([0xE0, 0x00])


def mqtt_availability_topic(discovery_prefix: str, node_id: str) -> str:
    """The shared topic this client's online/offline status is published to - see publish_mqtt()'s availability_topic."""
    return f"{discovery_prefix}/{node_id}/availability"


def publish_mqtt(
    host: str,
    port: int,
    client_id: str,
    publishes: List[Tuple[str, bytes, bool]],
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 5.0,
    use_tls: bool = False,
    insecure_tls: bool = False,
    availability_topic: Optional[str] = None,
) -> None:
    """Open one MQTT connection, publish every (topic, payload, retain) tuple at QoS 0, then disconnect.

    Args:
        publishes: (topic, payload, retain) tuples, sent in order on one
            connection - see build_ha_presence_publishes()/
            build_ha_absence_publishes().
        use_tls: Wrap the connection in TLS (port 8883 on most brokers)
            instead of plain TCP - see the CLI's --mqtt-tls.
        insecure_tls: Skip certificate hostname/chain verification -
            needed for a typical home broker's self-signed certificate,
            at the cost of not actually verifying it's who it claims to
            be. Only has any effect when use_tls is also set.
        availability_topic: If given, publishes "online" (retained) here
            right after connecting, and sets it as this connection's MQTT
            Last Will - the broker publishes "offline" (retained) here
            automatically if the connection ever drops without a clean
            DISCONNECT (a crash, a kill, lost power), instead of Home
            Assistant silently trusting a presence state that's gone
            stale. See build_ha_presence_publishes()'s own
            availability_topic parameter for wiring an entity to watch it.

    Raises:
        RuntimeError: the broker's CONNACK reported anything other than
            success (bad protocol version, bad credentials, not
            authorized, etc. - see MQTT 3.1.1 spec S3.2.2.3 for the full
            code list; this doesn't decode which one, just that it failed).
        OSError: the TCP connection itself failed (unreachable host,
            connection refused, timeout), or a TLS handshake/certificate
            failure under use_tls.
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            context = ssl.create_default_context()
            if insecure_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.sendall(_mqtt_connect_packet(
            client_id, username, password,
            will_topic=availability_topic, will_payload=b"offline", will_retain=True,
        ))
        connack = sock.recv(4)
        if len(connack) < 4 or connack[0] != 0x20 or connack[3] != 0x00:
            raise RuntimeError(f"MQTT broker rejected the connection (CONNACK: {connack!r})")
        if availability_topic:
            sock.sendall(_mqtt_publish_packet(availability_topic, b"online", retain=True))
        for topic, payload, retain in publishes:
            sock.sendall(_mqtt_publish_packet(topic, payload, retain))
        sock.sendall(_MQTT_DISCONNECT_PACKET)
    finally:
        sock.close()


def _mqtt_safe_id(key: str) -> str:
    """Turn a device identity (this script's is always a bare IP) into an MQTT-topic-safe, Home-Assistant-unique-id-safe token."""
    return _MQTT_TOPIC_SAFE_PATTERN.sub("_", key)


def build_ha_presence_publishes(
    devices: List[Device],
    discovery_prefix: str = "homeassistant",
    node_id: str = "mobile_network_scanner",
    availability_topic: Optional[str] = None,
) -> List[Tuple[str, bytes, bool]]:
    """Build Home Assistant MQTT Discovery config + ON-state publishes for every device in this scan.

    Each device becomes one `binary_sensor` entity with device_class
    "presence" - Home Assistant creates/updates it automatically the
    first time its config topic is published (MQTT Discovery), no manual
    YAML entity configuration needed on the Home Assistant side. Every
    publish is retained, so a restarted broker/Home Assistant still shows
    the last known state instead of "unavailable".

    A device that stops appearing in later scans simply stops being
    republished here - it does *not* get marked absent on its own. Pair
    this with build_ha_absence_publishes() and _find_missing_devices()'s
    own report, at the call site, to actively mark a dropped-off device
    away rather than leaving Home Assistant showing its stale last state.

    Args:
        availability_topic: If given (see mqtt_availability_topic()/
            publish_mqtt()), added to every entity's config so Home
            Assistant marks it "unavailable" - instead of trusting a
            possibly stale retained state - whenever this script itself
            stops publishing to it (a crash, a kill, lost power).
    """
    publishes: List[Tuple[str, bytes, bool]] = []
    for device in devices:
        safe_id = _mqtt_safe_id(_device_identity(device))
        unique_id = f"{node_id}_{safe_id}"
        name = device.get("hostname") or device.get("label") or device["ip"]
        state_topic = f"{discovery_prefix}/binary_sensor/{unique_id}/state"
        config_topic = f"{discovery_prefix}/binary_sensor/{unique_id}/config"
        config: dict = {
            "name": f"{name} presence",
            "unique_id": unique_id,
            "state_topic": state_topic,
            "payload_on": "ON",
            "payload_off": "OFF",
            "device_class": "presence",
        }
        if availability_topic:
            config["availability_topic"] = availability_topic
        config_payload = json.dumps(config).encode("utf-8")
        publishes.append((config_topic, config_payload, True))
        publishes.append((state_topic, b"ON", True))
    return publishes


def build_ha_absence_publishes(
    missing_devices: List[dict], discovery_prefix: str = "homeassistant", node_id: str = "mobile_network_scanner"
) -> List[Tuple[str, bytes, bool]]:
    """Build OFF-state publishes for devices _find_missing_devices() reports as no longer seen.

    Only the state topic is republished (OFF) - the config topic doesn't
    need resending, since Home Assistant already has the entity
    registered from whenever the device was last actually present.
    """
    publishes: List[Tuple[str, bytes, bool]] = []
    for entry in missing_devices:
        safe_id = _mqtt_safe_id(entry["key"])
        unique_id = f"{node_id}_{safe_id}"
        state_topic = f"{discovery_prefix}/binary_sensor/{unique_id}/state"
        publishes.append((state_topic, b"OFF", True))
    return publishes


def _resolve_mqtt_password(mqtt_password: Optional[str], mqtt_password_file: Optional[str]) -> Optional[str]:
    """Resolve the actual MQTT password to use: --mqtt-password itself, then --mqtt-password-file, then $MQTT_PASSWORD.

    --mqtt-password is visible to any other user on the same machine via
    `ps aux`/`/proc`, and lingers in shell history - a real exposure for
    the one credential this project's MQTT feature introduces. Kept as an
    option anyway (convenience, scripting) rather than removed, but a
    file or environment variable is the safer choice whenever one's
    available - tried in that order, after an explicit flag (which a
    caller presumably typed on purpose, override intended) but before
    falling through to the environment as the last, least-surprising
    "nothing configured" fallback.

    Raises:
        OSError: --mqtt-password-file was given but couldn't be read.
    """
    if mqtt_password is not None:
        return mqtt_password
    if mqtt_password_file:
        return Path(mqtt_password_file).read_text(encoding="utf-8").strip()
    return os.environ.get("MQTT_PASSWORD")


def main() -> None:
    """CLI entry point: parse arguments, run the scan, and print a results table."""
    # A small pre-parser for just --profile/--profile-file, so their
    # values are available before the real parser's parse_args() call -
    # _apply_profile() has to run (and install its coerced values as new
    # defaults) before that call, not after, for a profile's values to
    # actually take effect as fallbacks. add_help=False keeps this from
    # answering --help itself; the real parser below declares these same
    # two flags again so they show up in --help normally.
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--profile", type=str, default=None)
    pre_parser.add_argument("--profile-file", type=str, default=str(_DEFAULT_PROFILE_PATH))
    pre_args, _ = pre_parser.parse_known_args()

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "subnet",
        nargs="?",
        help="Subnet(s) to scan in CIDR notation, comma-separated for more than one, e.g. 192.168.1.0/24,10.0.0.0/24",
    )
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout in seconds per port probe (default: 0.5)")
    parser.add_argument(
        "--retries",
        type=int,
        default=0,
        help="Extra probe passes for hosts that didn't answer, to recover a device that missed one connection attempt due to transient flakiness (default: 0, i.e. a single pass) - see tcp_scan()",
    )
    parser.add_argument("--ports", type=str, default=None, help="Comma-separated TCP ports to probe (default: common ports)")
    parser.add_argument(
        "--exclude",
        type=str,
        default=None,
        metavar="LIST",
        help="Comma-separated IPs and/or CIDR ranges to skip entirely - no TCP connection is ever attempted against them (e.g. a fragile device that crashes under probes) - see _parse_exclusions()",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Skip the network scan and instead check this environment for everything this script can use (local subnet detection, TCP connectivity, cache writability, mDNS) - see run_doctor()",
    )
    parser.add_argument(
        "--mdns-timeout",
        type=float,
        default=0.3,
        help="Timeout in seconds for the mDNS/Bonjour hostname fallback, used when reverse DNS finds nothing (default: 0.3)",
    )
    parser.add_argument(
        "--watch",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Rescan repeatedly every SECONDS instead of running once, printing a NEW marker each time a device wasn't seen in any previous run (Ctrl+C to stop)",
    )
    parser.add_argument(
        "--no-track-devices",
        action="store_true",
        help="Don't persist or consult the known-devices registry - no NEW markers, and this run won't be remembered for next time",
    )
    parser.add_argument(
        "--forget-known-devices",
        action="store_true",
        help="Clear the known-devices registry before scanning, so every device found in this run is marked NEW",
    )
    parser.add_argument(
        "--set-label",
        action="append",
        default=[],
        metavar="KEY=LABEL",
        help="Assign a friendly label to a device (KEY is its IP address) shown instead of/alongside its hostname. Repeatable.",
    )
    parser.add_argument(
        "--remove-label",
        action="append",
        default=[],
        metavar="KEY",
        help="Remove a device's custom label (see --set-label). Repeatable.",
    )
    parser.add_argument(
        "--no-banners",
        action="store_true",
        help="Skip banner grabbing on each device's open port - faster, but loses a good identification hint for devices with no hostname",
    )
    parser.add_argument(
        "--no-risky-ports",
        action="store_true",
        help="Skip the risky-ports security check (see RISKY_PORTS) while keeping the general port probe for identification",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color in the output (also respects the NO_COLOR env var, and auto-disables when stdout isn't a terminal)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        metavar="FILE",
        help="Save this scan's results to FILE, independent of the known-devices registry - JSON, or CSV if FILE ends in .csv",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print nothing at all for a scan with no NEW/CHG/missing/risky devices to report - useful for --watch under cron/systemd, so only an interesting run produces output",
    )
    parser.add_argument(
        "--notify-webhook",
        type=str,
        default=None,
        metavar="URL",
        help="POST a summary to URL as {\"text\": ...} JSON (Slack-compatible) whenever a scan has a NEW/CHG/missing/risky device to report - see send_webhook_notification()",
    )
    parser.add_argument(
        "--log-history",
        type=str,
        default=None,
        metavar="FILE",
        help="Append every scan's results (even an empty one) to FILE as JSON Lines, independent of the known-devices registry - see append_scan_history()",
    )
    parser.add_argument(
        "--history-max-entries",
        type=int,
        default=_DEFAULT_HISTORY_MAX_ENTRIES,
        help=f"How many scans to keep in --log-history's log before dropping the oldest (default: {_DEFAULT_HISTORY_MAX_ENTRIES})",
    )
    parser.add_argument(
        "--diff-only",
        action="store_true",
        help="Under --watch, print only what changed since the previous tick instead of the full table every time - see diff_devices()",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        metavar="NAME",
        help=f"Load defaults from this named [section] in --profile-file (default: {_DEFAULT_PROFILE_PATH}) - explicit flags on the command line still override",
    )
    parser.add_argument(
        "--profile-file",
        type=str,
        default=str(_DEFAULT_PROFILE_PATH),
        metavar="FILE",
        help="INI file --profile reads its named section from",
    )
    parser.add_argument(
        "--metrics-file",
        type=str,
        default=None,
        metavar="FILE",
        help="Write this scan's device/new/risky counts to FILE in Prometheus text exposition format, for node_exporter's textfile collector - see write_prometheus_metrics()",
    )
    parser.add_argument(
        "--export-known-devices",
        type=str,
        default=None,
        metavar="FILE",
        help="Copy the known-devices registry to FILE (for backing it up or moving it to a new machine) and exit without scanning - see export_known_devices()",
    )
    parser.add_argument(
        "--import-known-devices",
        type=str,
        default=None,
        metavar="FILE",
        help="Merge FILE's known-devices registry into the current one (imported entries win on a collision) and exit without scanning - see import_known_devices()",
    )
    parser.add_argument(
        "--mqtt-host",
        type=str,
        default=None,
        metavar="HOST",
        help="Publish Home Assistant MQTT Discovery presence for every device found to this broker - see build_ha_presence_publishes()",
    )
    parser.add_argument("--mqtt-port", type=int, default=1883, help="MQTT broker port (default: 1883, or 8883 is common with --mqtt-tls)")
    parser.add_argument("--mqtt-username", type=str, default=None, help="MQTT broker username, if required")
    parser.add_argument(
        "--mqtt-password",
        type=str,
        default=None,
        help="MQTT broker password, if required - visible in `ps`/shell history; prefer --mqtt-password-file or $MQTT_PASSWORD",
    )
    parser.add_argument(
        "--mqtt-password-file",
        type=str,
        default=None,
        metavar="FILE",
        help="Read the MQTT broker password from FILE instead of --mqtt-password - see _resolve_mqtt_password()",
    )
    parser.add_argument(
        "--mqtt-client-id", type=str, default="mobile_network_scanner", help="MQTT client ID (default: mobile_network_scanner)"
    )
    parser.add_argument(
        "--mqtt-discovery-prefix",
        type=str,
        default="homeassistant",
        help="Home Assistant's MQTT Discovery topic prefix (default: homeassistant)",
    )
    parser.add_argument(
        "--mqtt-tls",
        action="store_true",
        help="Connect to the MQTT broker over TLS instead of plain TCP",
    )
    parser.add_argument(
        "--mqtt-insecure-tls",
        action="store_true",
        help="Under --mqtt-tls, skip certificate hostname/chain verification - needed for a typical self-signed home broker certificate, at the cost of not actually verifying it",
    )
    parser.add_argument(
        "--mqtt-no-availability",
        action="store_true",
        help="Don't publish an online/offline availability topic (or set an MQTT Last Will) alongside device presence - see mqtt_availability_topic()",
    )

    if pre_args.profile:
        profile = _load_profile(pre_args.profile, Path(pre_args.profile_file))
        if not profile:
            parser.error(f"--profile {pre_args.profile!r} not found in {pre_args.profile_file}")
        _apply_profile(parser, profile)

    args = parser.parse_args()

    color = _use_color(args.no_color)
    try:
        excluded_networks = _parse_exclusions(args.exclude) if args.exclude else []
    except ValueError as exc:
        parser.error(f"--exclude: {exc}")

    mqtt_password = None
    if args.mqtt_host:
        try:
            mqtt_password = _resolve_mqtt_password(args.mqtt_password, args.mqtt_password_file)
        except OSError as exc:
            parser.error(f"--mqtt-password-file: {exc}")

    if args.doctor:
        ok = run_doctor(color=color)
        raise SystemExit(0 if ok else 1)

    if args.export_known_devices:
        count = export_known_devices(Path(args.export_known_devices), known_devices_path=_KNOWN_DEVICES_PATH)
        print(f"Exported {count} known device(s) to {args.export_known_devices}.")
        raise SystemExit(0)

    if args.import_known_devices:
        count = import_known_devices(Path(args.import_known_devices), known_devices_path=_KNOWN_DEVICES_PATH)
        print(f"Imported {count} known device(s) from {args.import_known_devices}.")
        raise SystemExit(0)

    # If the user didn't pass a subnet, auto-detect it from the device's
    # own network configuration instead of forcing them to look it up.
    # Multiple comma-separated subnets are supported since this sandbox
    # can't auto-detect more than one for us (see the module docstring).
    subnets: List[str] = [s.strip() for s in args.subnet.split(",")] if args.subnet else [get_local_subnet()]

    # --ports takes a comma-separated string on the command line (e.g.
    # "22,80,443"); convert it to a tuple of ints, or fall back to the
    # built-in defaults if the flag wasn't given at all.
    ports: Sequence[int] = tuple(int(p) for p in args.ports.split(",")) if args.ports else DEFAULT_PORTS

    if args.forget_known_devices:
        _save_known_devices({}, _KNOWN_DEVICES_PATH)

    for spec in args.set_label:
        key, sep, label = spec.partition("=")
        if not sep:
            parser.error(f"--set-label expects KEY=LABEL, got {spec!r}")
        _set_label(key, label, known_devices_path=_KNOWN_DEVICES_PATH)
    for key in args.remove_label:
        _remove_label(key, known_devices_path=_KNOWN_DEVICES_PATH)

    # --diff-only's baseline: the previous tick's device list, or None
    # before the first tick has run at all (in which case there's
    # nothing yet to diff against, so run_once() falls back to printing
    # the full table that once). Declared here, one level up from
    # run_once(), so the closure below can update it across calls via
    # `nonlocal` - a --watch loop otherwise carries no state between ticks.
    previous_tick_devices: Optional[List[Device]] = None

    def run_once() -> None:
        """Scan once, mark/print NEW devices, and print the results table."""
        nonlocal previous_tick_devices
        if not args.quiet:
            print(f"Scanning {', '.join(subnets)} on ports {ports} ...")

        devices: List[Device] = scan_all_subnets(
            subnets,
            timeout=args.timeout,
            ports=ports,
            mdns_timeout=args.mdns_timeout,
            grab_banners=not args.no_banners,
            check_risky_ports=not args.no_risky_ports,
            excluded_networks=excluded_networks,
            retries=args.retries,
        )

        # Captured before being overwritten, and updated unconditionally
        # (even on an empty scan, even under --quiet) so that whichever
        # tick --diff-only's *next* call compares against is always the
        # immediately-preceding one - not a stale snapshot from several
        # ticks ago because an intervening tick returned early below.
        diff_baseline = previous_tick_devices
        previous_tick_devices = devices

        if args.log_history:
            append_scan_history(devices, Path(args.log_history), max_entries=args.history_max_entries)

        if not devices:
            if not args.quiet:
                print("No devices found.")
            if args.metrics_file:
                write_prometheus_metrics(Path(args.metrics_file), 0, 0, 0, time.time())
            return

        # known_devices_path is passed explicitly (rather than relying
        # on these functions' own default parameter) so that anything
        # overriding the module-level _KNOWN_DEVICES_PATH - a test, or a
        # future --known-devices-file flag - is actually respected here,
        # instead of these calls silently keeping whatever path was
        # bound to the default argument at function-definition time.
        #
        # _find_port_changes() must run before _mark_new_devices(): the
        # latter overwrites the registry with this scan's port, so the
        # "previous" value it needs would already be gone otherwise.
        port_changes = (
            {}
            if args.no_track_devices
            else _find_port_changes(devices, known_devices_path=_KNOWN_DEVICES_PATH)
        )
        is_new = {} if args.no_track_devices else _mark_new_devices(devices, known_devices_path=_KNOWN_DEVICES_PATH)
        missing = (
            []
            if args.no_track_devices
            else _find_missing_devices(devices, known_devices_path=_KNOWN_DEVICES_PATH)
        )
        labels = {} if args.no_track_devices else _load_labels(_KNOWN_DEVICES_PATH)
        risky_devices = [d for d in devices if d.get("risky_ports")]
        has_signal = bool(any(is_new.values()) or port_changes or missing or risky_devices)

        if args.notify_webhook and has_signal:
            message = _build_notification_message(devices, is_new, port_changes, missing, risky_devices)
            if message:
                send_webhook_notification(args.notify_webhook, message)

        # Metrics and MQTT presence are unconditional of --quiet/has_signal,
        # unlike the webhook above: a monitoring dashboard or a Home
        # Assistant presence sensor wants every tick's current state
        # ("0 new devices" is itself meaningful data), not just the
        # interesting ones --notify-webhook is about flagging.
        if args.metrics_file:
            new_count_for_metrics = sum(1 for v in is_new.values() if v)
            write_prometheus_metrics(
                Path(args.metrics_file), len(devices), new_count_for_metrics, len(risky_devices), time.time()
            )

        if args.mqtt_host:
            availability_topic = (
                None if args.mqtt_no_availability
                else mqtt_availability_topic(args.mqtt_discovery_prefix, args.mqtt_client_id)
            )
            try:
                mqtt_publishes = build_ha_presence_publishes(
                    devices, args.mqtt_discovery_prefix, args.mqtt_client_id, availability_topic=availability_topic
                )
                mqtt_publishes += build_ha_absence_publishes(missing, args.mqtt_discovery_prefix, args.mqtt_client_id)
                publish_mqtt(
                    args.mqtt_host, args.mqtt_port, args.mqtt_client_id, mqtt_publishes,
                    username=args.mqtt_username, password=mqtt_password,
                    use_tls=args.mqtt_tls, insecure_tls=args.mqtt_insecure_tls,
                    availability_topic=availability_topic,
                )
            except (OSError, RuntimeError) as exc:
                print(f"Warning: MQTT publish failed: {exc}", file=sys.stderr)

        if args.quiet and not has_signal:
            # Nothing worth reporting this run - true silence, not even
            # the table header, so a cron/systemd job produces zero
            # output on a boring scan instead of a full report every time.
            return

        if args.diff_only and diff_baseline is not None:
            # A short-circuit around the entire table/summary/detail-
            # section block below: diff_devices()'s added/removed/changed
            # output already conveys the same information, just unified
            # into one comparison instead of several separate registry-
            # based ones - see diff_devices()'s own docstring.
            diff = diff_devices(diff_baseline, devices)
            _print_diff_only(diff, color)
            if args.output:
                export_results(devices, Path(args.output))
                print(f"\nWrote {len(devices)} device(s) to {args.output}.")
            return

        # A leading marker column (rather than reflowing every other
        # column's width) keeps a NEW device visually obvious without
        # disturbing the table's layout when tracking is off.
        print(f"\n{'':<5}{'IP Address':<18}{'Port':<8}{'Service':<24}{'Hostname':<24}Banner")
        print("-" * 110)
        new_count = 0
        for device in devices:
            port = device["port"]
            # Fall back to just the bare port number for anything not in
            # PORT_SERVICES (e.g. a custom --ports value we don't recognize).
            service = PORT_SERVICES.get(port, "?")
            key = _device_identity(device)
            is_device_new = bool(is_new.get(key))
            if is_device_new:
                new_count += 1
            # A device can't be both: port_changes only contains devices
            # already in the registry, while NEW means the opposite.
            has_port_change = key in port_changes
            if is_device_new:
                marker = "NEW  "
            elif has_port_change:
                marker = "CHG  "
            else:
                marker = "     "
            banner = device.get("banner") or ""
            hostname_display = _display_hostname(device.get("hostname", ""), labels.get(key, ""))
            row = (
                f"{marker}{device['ip']:<18}{port:<8}{service:<24}"
                f"{hostname_display:<24}{banner}"
            )
            # A single color per row, not nested calls: _colorize() wraps
            # text in a start code and a reset, and ANSI's reset clears
            # *all* active styling, not just the innermost one - nesting
            # an inner colorize() inside an outer one would have the
            # inner reset kill the outer color partway through the line.
            # Priority (most to least important signal): risky, then
            # new, then a changed port - a NEW+risky device is still
            # visibly NEW from the literal marker text, just not also
            # green.
            if device.get("risky_ports"):
                row = _colorize(row, "red", color)
            elif is_device_new:
                row = _colorize(row, "green", color)
            elif has_port_change:
                row = _colorize(row, "yellow", color)
            print(row)

        print(f"\n{len(devices)} device(s) found.", end="")
        if not args.no_track_devices:
            print(f" {new_count} new since last seen.")
        else:
            print()

        if missing:
            print(f"\n{len(missing)} previously-seen device(s) not found in this scan:")
            for entry in missing:
                # A custom label (see --set-label) wins over the plain
                # hostname, same priority as the results table.
                label = entry.get("label") or entry.get("hostname") or ""
                suffix = f"  ({label})" if label else ""
                line = f"  {entry['key']:<18} last seen {entry.get('last_seen', '?')}{suffix}"
                print(_colorize(line, "dim", color))

        if port_changes:
            def _port_label(port: Optional[int]) -> str:
                return "(none)" if port is None else f"{PORT_SERVICES.get(port, '?')} ({port})"

            print(_colorize(f"\n{len(port_changes)} device(s) with a changed port since last seen:", "yellow", color))
            for device in devices:
                key = _device_identity(device)
                if key not in port_changes:
                    continue
                previous_port, current_port = port_changes[key]
                line = f"  {device['ip']:<18} {_port_label(previous_port)} -> {_port_label(current_port)}"
                print(_colorize(line, "yellow", color))

        if risky_devices:
            print(_colorize(f"\n⚠ {len(risky_devices)} device(s) exposing commonly-risky ports:", "yellow", color))
            all_risky_ports = set()
            for d in risky_devices:
                labels = ", ".join(f"{PORT_SERVICES.get(p, str(p))} ({p})" for p in d["risky_ports"])
                all_risky_ports.update(d["risky_ports"])
                line = f"  {d['ip']:<18} {labels}"
                print(_colorize(line, "red", color))
            print("\nWhy these are flagged:")
            for port in sorted(all_risky_ports):
                print(f"  {port:<6} {RISKY_PORTS[port]}")

        if args.output:
            export_results(devices, Path(args.output))
            print(f"\nWrote {len(devices)} device(s) to {args.output}.")

    if args.watch:
        if not args.quiet:
            print(f"Watch mode: rescanning every {args.watch:g}s (Ctrl+C to stop).")
        try:
            while True:
                if not args.quiet:
                    print(f"\n=== {datetime.now().isoformat(timespec='seconds')} ===")
                run_once()
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        run_once()


if __name__ == "__main__":
    main()
