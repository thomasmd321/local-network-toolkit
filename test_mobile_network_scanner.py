import csv
import ipaddress
import json
import socket
import struct
import sys
import threading
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

import mobile_network_scanner as ms


class TestGetLocalSubnet:
    def test_derives_slash_24_from_local_ip(self):
        fake_sock = MagicMock()
        fake_sock.getsockname.return_value = ("10.0.0.7", 12345)
        fake_sock.__enter__.return_value = fake_sock

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.get_local_subnet() == "10.0.0.0/24"


class TestProbeHost:
    def test_returns_matched_port_when_one_accepts_connection(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect_ex.side_effect = [1, 0]

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.probe_host("192.168.1.1", [80, 443], timeout=0.1) == 443

    def test_returns_none_when_no_ports_accept_connection(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect_ex.return_value = 1

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.probe_host("192.168.1.1", [80, 443], timeout=0.1) is None

    def test_stops_probing_after_first_success(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect_ex.return_value = 0

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ms.probe_host("192.168.1.1", [80, 443, 8080], timeout=0.1)

        assert fake_sock.connect_ex.call_count == 1


class TestSummarizeBanner:
    def test_prefers_server_header_over_status_line(self):
        data = b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.55\r\nContent-Length: 0\r\n\r\n"
        assert ms._summarize_banner(data) == "HTTP/1.1 200 OK  |  Server: lighttpd/1.4.55"

    def test_returns_first_line_when_no_server_header(self):
        data = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"
        assert ms._summarize_banner(data) == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"

    def test_returns_empty_string_for_blank_data(self):
        assert ms._summarize_banner(b"\r\n\r\n   \r\n") == ""

    def test_truncates_long_lines(self):
        data = ("x" * 300).encode("ascii") + b"\r\n"
        assert len(ms._summarize_banner(data)) == 120


class TestGrabBanner:
    def test_sends_head_request_on_http_port(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.grab_banner("192.168.1.1", 80, timeout=0.5)

        assert "nginx" in result
        sent = fake_sock.sendall.call_args[0][0]
        assert sent.startswith(b"HEAD / HTTP/1.0")

    def test_reads_unprompted_banner_on_non_http_port(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1\r\n"

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.grab_banner("192.168.1.1", 22, timeout=0.5)

        assert result == "SSH-2.0-OpenSSH_8.9p1"
        fake_sock.sendall.assert_not_called()

    def test_wraps_https_port_in_tls(self):
        fake_raw_sock = MagicMock()
        fake_raw_sock.__enter__.return_value = fake_raw_sock
        fake_wrapped_sock = MagicMock()
        fake_wrapped_sock.recv.return_value = b"HTTP/1.1 401 Unauthorized\r\nServer: lighttpd\r\n\r\n"

        fake_context = MagicMock()
        fake_context.wrap_socket.return_value = fake_wrapped_sock

        with patch("mobile_network_scanner.socket.socket", return_value=fake_raw_sock), \
                patch("mobile_network_scanner.ssl.create_default_context", return_value=fake_context):
            result = ms.grab_banner("192.168.1.1", 8443, timeout=0.5)

        assert "lighttpd" in result
        assert fake_context.check_hostname is False
        fake_wrapped_sock.sendall.assert_called_once()

    def test_returns_empty_string_on_connection_failure(self):
        with patch("mobile_network_scanner.socket.socket", side_effect=OSError("Connection refused")):
            assert ms.grab_banner("192.168.1.1", 80, timeout=0.5) == ""

    def test_falls_back_to_http_probe_on_unrecognized_silent_port(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        # First recv() (passive listen) times out; second recv() (after
        # the HTTP fallback probe) returns a real response.
        fake_sock.recv.side_effect = [socket.timeout, b"HTTP/1.1 200 OK\r\nServer: mystery-iot\r\n\r\n"]

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.grab_banner("192.168.1.1", 9999, timeout=0.5)

        assert "mystery-iot" in result
        fake_sock.sendall.assert_called_once()

    def test_does_not_send_http_probe_when_unrecognized_port_already_answered(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recv.return_value = b"220 example-ftp ready\r\n"

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.grab_banner("192.168.1.1", 9999, timeout=0.5)

        assert result == "220 example-ftp ready"
        fake_sock.sendall.assert_not_called()


class TestProbeTcpPort:
    def test_returns_true_when_port_accepts_connection(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect_ex.return_value = 0

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms._probe_tcp_port("192.168.1.1", 80, timeout=0.1) is True

    def test_returns_false_when_port_refuses_connection(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect_ex.return_value = 1

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms._probe_tcp_port("192.168.1.1", 80, timeout=0.1) is False


class TestFindRiskyPorts:
    def test_reports_all_open_risky_ports_not_just_the_first(self):
        def fake_probe(ip, port, timeout):
            return port in (23, 3389)

        with patch("mobile_network_scanner._probe_tcp_port", side_effect=fake_probe):
            assert ms._find_risky_ports("192.168.1.1", timeout=0.1) == [23, 3389]

    def test_returns_empty_list_when_none_open(self):
        with patch("mobile_network_scanner._probe_tcp_port", return_value=False):
            assert ms._find_risky_ports("192.168.1.1", timeout=0.1) == []


class TestAttachRiskyPorts:
    def test_fills_in_risky_ports_for_each_device(self):
        devices = [{"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}]

        with patch("mobile_network_scanner._find_risky_ports", return_value=[23]):
            result = ms._attach_risky_ports(devices, timeout=0.1)

        assert result[0]["risky_ports"] == [23]


class TestUseColor:
    def test_disabled_by_no_color_flag(self):
        with patch("mobile_network_scanner.sys.stdout.isatty", return_value=True), \
                patch.dict("mobile_network_scanner.os.environ", {}, clear=True):
            assert ms._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self):
        with patch("mobile_network_scanner.sys.stdout.isatty", return_value=True), \
                patch.dict("mobile_network_scanner.os.environ", {"NO_COLOR": "1"}):
            assert ms._use_color(no_color_flag=False) is False

    def test_disabled_when_stdout_is_not_a_tty(self):
        with patch("mobile_network_scanner.sys.stdout.isatty", return_value=False), \
                patch.dict("mobile_network_scanner.os.environ", {}, clear=True):
            assert ms._use_color(no_color_flag=False) is False

    def test_enabled_when_none_of_the_above_apply(self):
        with patch("mobile_network_scanner.sys.stdout.isatty", return_value=True), \
                patch.dict("mobile_network_scanner.os.environ", {}, clear=True):
            assert ms._use_color(no_color_flag=False) is True


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        result = ms._colorize("NEW", "green", enabled=True)
        assert result == f"{ms._ANSI_CODES['green']}NEW{ms._ANSI_CODES['reset']}"

    def test_returns_plain_text_when_disabled(self):
        assert ms._colorize("NEW", "green", enabled=False) == "NEW"


class TestExportResults:
    def test_writes_json_by_default(self, tmp_path):
        path = tmp_path / "scan.json"
        devices = [{"ip": "192.168.1.1", "hostname": "router.local", "port": 80, "banner": "", "risky_ports": []}]

        ms.export_results(devices, path)

        assert json.loads(path.read_text(encoding="utf-8")) == devices

    def test_writes_json_for_an_unrecognized_extension(self, tmp_path):
        path = tmp_path / "scan.txt"
        devices = [{"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}]

        ms.export_results(devices, path)

        assert json.loads(path.read_text(encoding="utf-8")) == devices

    def test_writes_csv_when_path_ends_in_dot_csv(self, tmp_path):
        path = tmp_path / "scan.csv"
        devices = [{
            "ip": "192.168.1.1", "hostname": "router.local", "port": 80,
            "banner": "Server: nginx", "risky_ports": [23, 445],
        }]

        ms.export_results(devices, path)

        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        assert rows == [{
            "ip": "192.168.1.1", "hostname": "router.local", "port": "80",
            "banner": "Server: nginx", "risky_ports": "23;445",
        }]

    def test_csv_uses_empty_string_for_empty_risky_ports(self, tmp_path):
        path = tmp_path / "scan.csv"
        devices = [{"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}]

        ms.export_results(devices, path)

        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        assert rows[0]["risky_ports"] == ""

    def test_csv_column_order_matches_fieldnames(self, tmp_path):
        path = tmp_path / "scan.csv"
        devices = [{"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}]

        ms.export_results(devices, path)

        header = path.read_text(encoding="utf-8").splitlines()[0]
        assert header == "ip,hostname,port,banner,risky_ports"


class TestAppendScanHistory:
    def test_appends_one_json_line_per_call(self, tmp_path):
        path = tmp_path / "history.jsonl"
        devices = [{"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}]

        ms.append_scan_history(devices, path)
        ms.append_scan_history(devices, path)

        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2

    def test_each_line_records_devices_and_a_timestamp(self, tmp_path):
        path = tmp_path / "history.jsonl"
        devices = [{"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}]

        ms.append_scan_history(devices, path)

        entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert entry["devices"] == devices
        assert "timestamp" in entry

    def test_logs_an_empty_scan_too(self, tmp_path):
        path = tmp_path / "history.jsonl"

        ms.append_scan_history([], path)

        entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert entry["devices"] == []

    def test_creates_parent_directories(self, tmp_path):
        path = tmp_path / "nested" / "history.jsonl"

        ms.append_scan_history([], path)

        assert path.exists()

    def test_does_not_raise_when_directory_creation_fails(self, tmp_path):
        path = tmp_path / "history.jsonl"
        with patch("mobile_network_scanner.Path.mkdir", side_effect=OSError("Permission denied")):
            ms.append_scan_history([], path)  # Should not raise.

    def test_trims_oldest_entries_once_over_the_cap(self, tmp_path):
        path = tmp_path / "history.jsonl"
        for i in range(5):
            ms.append_scan_history([{"ip": f"192.168.1.{i}"}], path, max_entries=3)

        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 3
        kept_ips = [json.loads(line)["devices"][0]["ip"] for line in lines]
        assert kept_ips == ["192.168.1.2", "192.168.1.3", "192.168.1.4"]

    def test_does_not_rewrite_the_file_while_under_the_cap(self, tmp_path):
        path = tmp_path / "history.jsonl"
        ms.append_scan_history([{"ip": "192.168.1.1"}], path, max_entries=200)

        with patch("mobile_network_scanner.Path.write_text") as mock_write_text:
            ms.append_scan_history([{"ip": "192.168.1.2"}], path, max_entries=200)

        mock_write_text.assert_not_called()


class TestBuildNotificationMessage:
    def test_returns_empty_string_when_nothing_to_report(self):
        message = ms._build_notification_message([], {}, {}, [], [])
        assert message == ""

    def test_includes_new_devices(self):
        devices = [{"ip": "192.168.1.1", "hostname": "phone.local"}]
        is_new = {"192.168.1.1": True}

        message = ms._build_notification_message(devices, is_new, {}, [], [])

        assert "1 new device(s):" in message
        assert "192.168.1.1  phone.local" in message

    def test_new_device_with_no_hostname_shows_placeholder(self):
        devices = [{"ip": "192.168.1.1", "hostname": ""}]
        is_new = {"192.168.1.1": True}

        message = ms._build_notification_message(devices, is_new, {}, [], [])

        assert "(no hostname)" in message

    def test_includes_port_changes(self):
        devices = [{"ip": "192.168.1.1", "hostname": ""}]
        port_changes = {"192.168.1.1": (80, 22)}

        message = ms._build_notification_message(devices, {}, port_changes, [], [])

        assert "1 device(s) with a changed port:" in message
        assert "http (80) -> ssh (22)" in message

    def test_includes_missing_devices(self):
        missing = [{"key": "192.168.1.1", "hostname": "router.local"}]

        message = ms._build_notification_message([], {}, {}, missing, [])

        assert "1 previously-seen device(s) missing:" in message
        assert "192.168.1.1 (router.local)" in message

    def test_missing_device_label_takes_priority_over_hostname(self):
        missing = [{"key": "192.168.1.1", "hostname": "router.local", "label": "Kitchen Echo"}]

        message = ms._build_notification_message([], {}, {}, missing, [])

        assert "(Kitchen Echo)" in message
        assert "router.local" not in message

    def test_includes_risky_devices(self):
        risky = [{"ip": "192.168.1.1", "risky_ports": [445, 3389]}]

        message = ms._build_notification_message([], {}, {}, [], risky)

        assert "1 device(s) exposing a risky port:" in message
        assert "smb (445), rdp (3389)" in message

    def test_combines_multiple_categories_with_blank_line_between(self):
        devices = [{"ip": "192.168.1.1", "hostname": "phone.local"}]
        is_new = {"192.168.1.1": True}
        risky = [{"ip": "192.168.1.2", "risky_ports": [23]}]

        message = ms._build_notification_message(devices, is_new, {}, [], risky)

        assert "1 new device(s):" in message
        assert "1 device(s) exposing a risky port:" in message
        assert "\n\n" in message


class TestSendWebhookNotification:
    def test_returns_true_on_a_2xx_response(self):
        fake_response = MagicMock()
        fake_response.status = 200
        fake_response.__enter__.return_value = fake_response

        with patch("mobile_network_scanner.urllib.request.urlopen", return_value=fake_response) as mock_urlopen:
            result = ms.send_webhook_notification("https://example.com/hook", "hello")

        assert result is True
        request = mock_urlopen.call_args[0][0]
        assert request.full_url == "https://example.com/hook"
        assert json.loads(request.data) == {"text": "hello"}
        assert request.get_header("Content-type") == "application/json"

    def test_returns_false_on_a_non_2xx_response(self):
        fake_response = MagicMock()
        fake_response.status = 500
        fake_response.__enter__.return_value = fake_response

        with patch("mobile_network_scanner.urllib.request.urlopen", return_value=fake_response):
            assert ms.send_webhook_notification("https://example.com/hook", "hello") is False

    def test_returns_false_and_does_not_raise_on_network_error(self):
        with patch("mobile_network_scanner.urllib.request.urlopen", side_effect=urllib.error.URLError("no route")):
            assert ms.send_webhook_notification("https://example.com/hook", "hello") is False


class TestCheckLocalSubnet:
    def test_reports_the_detected_subnet(self):
        with patch("mobile_network_scanner.get_local_subnet", return_value="192.168.1.0/24"):
            ok, detail = ms._check_local_subnet()
        assert ok is True
        assert "192.168.1.0/24" in detail

    def test_reports_failure_when_detection_raises(self):
        with patch("mobile_network_scanner.get_local_subnet", side_effect=OSError("no route")):
            ok, detail = ms._check_local_subnet()
        assert ok is False
        assert "Couldn't detect" in detail


class TestCheckTcpConnectivity:
    def test_reports_ok_when_connect_succeeds(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ok, detail = ms._check_tcp_connectivity()
        assert ok is True

    def test_reports_failure_when_connect_raises(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect.side_effect = OSError("timed out")
        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ok, detail = ms._check_tcp_connectivity()
        assert ok is False
        assert "Couldn't open" in detail


class TestCheckCacheWritable:
    def test_reports_writable_directory(self, tmp_path):
        with patch("mobile_network_scanner.Path.home", return_value=tmp_path):
            ok, detail = ms._check_cache_writable()
        assert ok is True
        assert str(tmp_path / ".cache") in detail

    def test_reports_unwritable_directory(self, tmp_path):
        with patch("mobile_network_scanner.Path.home", return_value=tmp_path), \
                patch("mobile_network_scanner.Path.write_text", side_effect=OSError("Permission denied")):
            ok, detail = ms._check_cache_writable()
        assert ok is False
        assert "not writable" in detail


class TestCheckMdnsMulticast:
    def test_reports_ok_when_send_succeeds(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ok, detail = ms._check_mdns_multicast()
        assert ok is True

    def test_tolerates_bind_or_join_failure_and_still_tries_to_send(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.bind.side_effect = OSError("Address already in use")
        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ok, detail = ms._check_mdns_multicast()
        assert ok is True
        fake_sock.sendto.assert_called_once()

    def test_reports_failure_when_send_is_denied(self):
        # The real iOS failure mode: bind/join succeed, the send itself
        # fails with OSError(65, 'No route to host').
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.sendto.side_effect = OSError(65, "No route to host")
        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ok, detail = ms._check_mdns_multicast()
        assert ok is False
        assert "Local Network Privacy" in detail


class TestRunDoctor:
    def test_returns_true_when_every_check_passes(self, capsys):
        checks = (("Check A", lambda: (True, "fine")), ("Check B", lambda: (True, "also fine")))
        with patch("mobile_network_scanner._DOCTOR_CHECKS", checks):
            assert ms.run_doctor(color=False) is True
        assert "Everything checks out." in capsys.readouterr().out

    def test_returns_false_when_any_check_fails(self, capsys):
        checks = (("Check A", lambda: (True, "fine")), ("Check B", lambda: (False, "not fine")))
        with patch("mobile_network_scanner._DOCTOR_CHECKS", checks):
            assert ms.run_doctor(color=False) is False
        out = capsys.readouterr().out
        assert "not fine" in out
        assert "Some checks reported a limitation" in out


class TestDnsNameEncoding:
    def test_round_trips_a_simple_name(self):
        encoded = ms._encode_dns_name("72.1.168.192.in-addr.arpa")
        # Decoding needs a full "message" buffer to index into, even
        # though this name has no compression pointers to jump through.
        name, offset = ms._decode_dns_name(encoded, 0)

        assert name == "72.1.168.192.in-addr.arpa"
        assert offset == len(encoded)

    def test_decodes_a_compression_pointer(self):
        # Simulates two records sharing a ".local" suffix: the first
        # spells it out at offset 0, the second just points back to it.
        suffix = ms._encode_dns_name("local")
        pointer = bytes([0xC0, 0x00])  # Pointer to offset 0.
        message = suffix + pointer

        name, offset = ms._decode_dns_name(message, len(suffix))

        assert name == "local"
        # The returned offset should be right after the 2-byte pointer,
        # not wherever the pointer jumped to.
        assert offset == len(suffix) + 2


class TestBuildMdnsPtrQuery:
    def test_builds_a_well_formed_single_question_query(self):
        query = ms._build_mdns_ptr_query("72.1.168.192.in-addr.arpa")

        header = struct.unpack(">HHHHHH", query[:12])
        assert header == (0, 0, 1, 0, 0, 0)  # ID, flags, QD/AN/NS/ARcount

        qname, offset = ms._decode_dns_name(query, 12)
        assert qname == "72.1.168.192.in-addr.arpa"

        qtype, qclass = struct.unpack(">HH", query[offset:offset + 4])
        assert qtype == ms._DNS_TYPE_PTR
        # The QU bit must be set - see _MDNS_QU_BIT's comment for why
        # this implementation depends on getting a unicast reply.
        assert qclass == ms._DNS_CLASS_IN | ms._MDNS_QU_BIT


def _build_fake_ptr_response(qname: str, answer_name: str, target: str) -> bytes:
    """Build a minimal, valid mDNS response with one PTR answer, for tests."""
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)  # 0 questions, 1 answer
    rdata = ms._encode_dns_name(target)
    answer = (
        ms._encode_dns_name(answer_name)
        + struct.pack(">HH", ms._DNS_TYPE_PTR, ms._DNS_CLASS_IN)
        + struct.pack(">I", 120)  # TTL
        + struct.pack(">H", len(rdata))
        + rdata
    )
    return header + answer


class TestExtractPtrHostname:
    def test_extracts_hostname_from_matching_answer(self):
        qname = "72.1.168.192.in-addr.arpa"
        message = _build_fake_ptr_response(qname, qname, "Chromecast-abc123.local.")

        assert ms._extract_ptr_hostname(message, qname) == "Chromecast-abc123.local"

    def test_ignores_answer_for_a_different_name(self):
        message = _build_fake_ptr_response(
            "9.1.168.192.in-addr.arpa", "9.1.168.192.in-addr.arpa", "other-device.local."
        )

        assert ms._extract_ptr_hostname(message, "72.1.168.192.in-addr.arpa") == ""

    def test_returns_empty_string_for_garbage_input(self):
        assert ms._extract_ptr_hostname(b"\x00\x01", "72.1.168.192.in-addr.arpa") == ""


def _build_a_record(name: str, ip: str) -> bytes:
    """Build a single raw DNS A record, for tests."""
    return (
        ms._encode_dns_name(name)
        + struct.pack(">HH", ms._DNS_TYPE_A, ms._DNS_CLASS_IN)
        + struct.pack(">I", 120)  # TTL
        + struct.pack(">H", 4)  # RDLENGTH: an IPv4 address is 4 bytes
        + socket.inet_aton(ip)
    )


def _build_srv_record(instance_name: str, target: str, port: int = 8009) -> bytes:
    """Build a single raw DNS SRV record, for tests."""
    rdata = struct.pack(">HHH", 0, 0, port) + ms._encode_dns_name(target)  # priority, weight, port, target
    return (
        ms._encode_dns_name(instance_name)
        + struct.pack(">HH", ms._DNS_TYPE_SRV, ms._DNS_CLASS_IN)
        + struct.pack(">I", 120)  # TTL
        + struct.pack(">H", len(rdata))
        + rdata
    )


def _build_fake_service_response(*records: bytes, answer_count: int = 0, additional_count: int = 0) -> bytes:
    """Wrap prebuilt records in a minimal mDNS response header, for tests."""
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, answer_count, 0, additional_count)
    return header + b"".join(records)


class TestCollectServiceRecords:
    def test_collects_a_and_srv_records_regardless_of_section(self):
        a_record = _build_a_record("Chromecast-abc123.local", "192.168.1.72")
        srv_record = _build_srv_record("Living Room TV._googlecast._tcp.local", "Chromecast-abc123.local")
        # A real response often splits these: SRV as an answer, its
        # supporting A record as "additional" - exercise that split.
        message = _build_fake_service_response(srv_record, a_record, answer_count=1, additional_count=1)

        host_to_ip: dict = {}
        instance_to_host: dict = {}
        ms._collect_service_records(message, host_to_ip, instance_to_host)

        assert host_to_ip == {"chromecast-abc123.local": "192.168.1.72"}
        assert instance_to_host == {"Living Room TV._googlecast._tcp.local": "chromecast-abc123.local"}

    def test_ignores_unrelated_record_types(self):
        ptr_record = _build_fake_ptr_response("x", "x", "y")  # Includes its own header - just reuse the answer bytes.
        # Strip the fake header this helper adds, since we only want the
        # record bytes to feed into _collect_service_records directly.
        message = _build_fake_service_response(ptr_record[12:], answer_count=1)

        host_to_ip: dict = {}
        instance_to_host: dict = {}
        ms._collect_service_records(message, host_to_ip, instance_to_host)

        assert host_to_ip == {}
        assert instance_to_host == {}


class TestMdnsServiceLookup:
    def test_joins_srv_and_a_records_into_ip_to_name_map(self):
        a_record = _build_a_record("Chromecast-abc123.local", "192.168.1.72")
        srv_record = _build_srv_record("Living Room TV._googlecast._tcp.local", "Chromecast-abc123.local")
        response = _build_fake_service_response(srv_record, a_record, answer_count=2)

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(response, ("192.168.1.72", 5353)), socket.timeout]

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.2)

        assert result == {"192.168.1.72": "Living Room TV"}

    def test_combines_records_split_across_multiple_packets(self):
        srv_record = _build_srv_record("Living Room TV._googlecast._tcp.local", "Chromecast-abc123.local")
        a_record = _build_a_record("Chromecast-abc123.local", "192.168.1.72")
        srv_packet = _build_fake_service_response(srv_record, answer_count=1)
        a_packet = _build_fake_service_response(a_record, answer_count=1)

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(srv_packet, ("x", 5353)), (a_packet, ("x", 5353)), socket.timeout]

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.2)

        assert result == {"192.168.1.72": "Living Room TV"}

    def test_omits_instance_with_no_matching_a_record(self):
        srv_record = _build_srv_record("Living Room TV._googlecast._tcp.local", "Chromecast-abc123.local")
        response = _build_fake_service_response(srv_record, answer_count=1)

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(response, ("x", 5353)), socket.timeout]

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.2)

        assert result == {}

    def test_returns_empty_dict_when_nothing_answers(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.01) == {}

    def test_returns_empty_dict_when_multicast_send_is_denied(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.sendto.side_effect = OSError("Local network access denied")

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.5) == {}

    def test_binds_to_mdns_port_and_joins_the_multicast_group(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.01)

        fake_sock.bind.assert_called_once_with(("", 5353))
        join_call = next(
            call for call in fake_sock.setsockopt.call_args_list if call.args[0:2] == (socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP)
        )
        assert join_call.args[2] == struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)

    def test_still_queries_when_bind_or_group_join_fails(self):
        # A sandboxed environment (iOS) may refuse the bind/join - the
        # lookup should still send its query and listen on whatever
        # ordinary ephemeral-port socket resulted, rather than giving up.
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.bind.side_effect = OSError("Address already in use")
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.01)

        assert result == {}
        fake_sock.sendto.assert_called_once()


class TestMdnsReverseLookup:
    def test_returns_hostname_from_first_matching_response(self):
        qname = "72.1.168.192.in-addr.arpa"
        response = _build_fake_ptr_response(qname, qname, "Chromecast-abc123.local.")

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.return_value = (response, ("192.168.1.72", 5353))

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            hostname = ms.mdns_reverse_lookup("192.168.1.72", timeout=0.5)

        assert hostname == "Chromecast-abc123.local"
        fake_sock.sendto.assert_called_once()
        assert fake_sock.sendto.call_args[0][1] == ms._MDNS_GROUP

    def test_skips_irrelevant_packets_before_the_matching_one(self):
        qname = "72.1.168.192.in-addr.arpa"
        unrelated = _build_fake_ptr_response("9.1.168.192.in-addr.arpa", "9.1.168.192.in-addr.arpa", "other.local.")
        matching = _build_fake_ptr_response(qname, qname, "Chromecast-abc123.local.")

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(unrelated, ("x", 5353)), (matching, ("x", 5353))]

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.mdns_reverse_lookup("192.168.1.72", timeout=0.5) == "Chromecast-abc123.local"

    def test_returns_empty_string_on_timeout(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.mdns_reverse_lookup("192.168.1.72", timeout=0.01) == ""

    def test_returns_empty_string_when_multicast_send_is_denied(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.sendto.side_effect = OSError("Local network access denied")

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.mdns_reverse_lookup("192.168.1.72", timeout=0.5) == ""


class TestResolveHostname:
    def test_prefers_reverse_dns_when_available(self):
        with patch("mobile_network_scanner.socket.gethostbyaddr", return_value=("nas.local", [], [])), \
                patch("mobile_network_scanner.mdns_reverse_lookup") as mock_mdns:
            assert ms._resolve_hostname("192.168.1.157", mdns_timeout=0.3) == "nas.local"

        mock_mdns.assert_not_called()

    def test_falls_back_to_mdns_when_reverse_dns_fails(self):
        with patch("mobile_network_scanner.socket.gethostbyaddr", side_effect=socket.herror), \
                patch("mobile_network_scanner.mdns_reverse_lookup", return_value="Chromecast-abc123.local") as mock_mdns:
            assert ms._resolve_hostname("192.168.1.72", mdns_timeout=0.3) == "Chromecast-abc123.local"

        mock_mdns.assert_called_once_with("192.168.1.72", timeout=0.3)


class TestTcpScan:
    def test_returns_only_live_hosts_sorted_by_ip(self):
        def fake_probe(ip, ports, timeout):
            return 80 if ip in ("192.168.1.2", "192.168.1.10") else None

        with patch("mobile_network_scanner.probe_host", side_effect=fake_probe), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan("192.168.1.0/28", timeout=0.1, max_workers=8)

        ips = [d["ip"] for d in devices]
        assert ips == sorted(ips, key=lambda ip: tuple(int(p) for p in ip.split(".")))
        assert set(ips) == {"192.168.1.2", "192.168.1.10"}

    def test_excluded_hosts_are_never_probed_at_all(self):
        probed_ips = []

        def fake_probe(ip, ports, timeout):
            probed_ips.append(ip)
            return 80

        with patch("mobile_network_scanner.probe_host", side_effect=fake_probe), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan(
                "192.168.1.0/29", timeout=0.1, max_workers=8,
                excluded_networks=ms._parse_exclusions("192.168.1.1,192.168.1.2"),
            )

        assert "192.168.1.1" not in probed_ips
        assert "192.168.1.2" not in probed_ips
        assert "192.168.1.1" not in [d["ip"] for d in devices]
        assert "192.168.1.2" not in [d["ip"] for d in devices]

    def test_zero_retries_probes_each_host_only_once(self):
        probe_calls = []

        def fake_probe(ip, ports, timeout):
            probe_calls.append(ip)
            return None

        with patch("mobile_network_scanner.probe_host", side_effect=fake_probe), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]):
            ms.tcp_scan("192.168.1.0/29", timeout=0.1, max_workers=8)

        assert len(probe_calls) == len(set(probe_calls))

    def test_retries_recovers_a_host_that_missed_the_first_pass(self):
        call_counts: dict = {}

        def fake_probe(ip, ports, timeout):
            call_counts[ip] = call_counts.get(ip, 0) + 1
            if ip == "192.168.1.5":
                # Missed on the first pass, answers from the first retry on.
                return None if call_counts[ip] == 1 else 80
            return None

        with patch("mobile_network_scanner.probe_host", side_effect=fake_probe), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan("192.168.1.0/29", timeout=0.1, max_workers=8, retries=1)

        assert "192.168.1.5" in [d["ip"] for d in devices]
        assert call_counts["192.168.1.5"] == 2

    def test_retries_do_not_reprobe_hosts_that_already_answered(self):
        probe_calls = []

        def fake_probe(ip, ports, timeout):
            probe_calls.append(ip)
            return 80  # Every host answers on the very first pass.

        with patch("mobile_network_scanner.probe_host", side_effect=fake_probe), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            ms.tcp_scan("192.168.1.0/29", timeout=0.1, max_workers=8, retries=3)

        # None of the 3 retry passes should probe anyone again, since
        # every host already has a match after the first pass.
        assert len(probe_calls) == len(set(probe_calls))

    def test_attaches_hostname_and_matched_port_when_available(self):
        # Port 80, not 8009 (the Chromecast port), so this doesn't also
        # trigger the Cast-service-discovery path - see TestTcpScan's
        # cast-specific tests below for that.
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value="phone.local"):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert {
            "ip": "192.168.1.1", "hostname": "phone.local", "port": 80, "banner": "", "risky_ports": [],
        } in devices

    def test_falls_back_to_mdns_when_reverse_dns_has_no_hostname(self):
        # Exercises the real _resolve_hostname (not mocked out), so this
        # confirms tcp_scan actually wires the mDNS fallback in, not just
        # that _resolve_hostname works in isolation. Port 80 avoids also
        # triggering Cast service discovery (tested separately below).
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner.socket.gethostbyaddr", side_effect=socket.gaierror), \
                patch("mobile_network_scanner.mdns_reverse_lookup", return_value="some-device.local"):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4, mdns_timeout=0.2)

        assert all(d["hostname"] == "some-device.local" for d in devices)

    def test_uses_cast_service_name_when_chromecast_port_matches(self):
        with patch("mobile_network_scanner.probe_host", return_value=8009), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner.mdns_service_lookup", return_value={"192.168.1.1": "Living Room TV"}), \
                patch("mobile_network_scanner._resolve_hostname", return_value="should-not-be-used"):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4, mdns_timeout=0.2)

        assert {
            "ip": "192.168.1.1", "hostname": "Living Room TV", "port": 8009, "banner": "", "risky_ports": [],
        } in devices

    def test_falls_back_to_resolve_hostname_when_cast_lookup_has_no_name_for_ip(self):
        # mdns_service_lookup() might name some Cast devices on the
        # subnet but not this particular one (e.g. its A record arrived
        # too late) - it should still get a chance via the normal path.
        with patch("mobile_network_scanner.probe_host", return_value=8009), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner.mdns_service_lookup", return_value={}), \
                patch("mobile_network_scanner._resolve_hostname", return_value="fallback.local"):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4, mdns_timeout=0.2)

        assert all(d["hostname"] == "fallback.local" for d in devices)

    def test_skips_cast_lookup_when_no_chromecast_port_present(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner.mdns_service_lookup") as mock_cast_lookup, \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        mock_cast_lookup.assert_not_called()

    def test_missing_hostname_defaults_to_empty_string(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert all(d["hostname"] == "" for d in devices)

    def test_no_live_hosts_returns_empty_list(self):
        with patch("mobile_network_scanner.probe_host", return_value=None):
            assert ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4) == []

    def test_uses_default_ports_when_none_specified(self):
        captured_ports = []

        def fake_probe(ip, ports, timeout):
            captured_ports.append(ports)
            return None

        with patch("mobile_network_scanner.probe_host", side_effect=fake_probe):
            ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert all(ports == ms.DEFAULT_PORTS for ports in captured_ports)

    def test_attaches_banner_from_grab_banner_for_each_matched_port(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value="Server: lighttpd"), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert all(d["banner"] == "Server: lighttpd" for d in devices)

    def test_grab_banner_called_with_each_device_matched_port(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value="") as mock_grab_banner, \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        mock_grab_banner.assert_any_call("192.168.1.1", 80, 0.1)
        mock_grab_banner.assert_any_call("192.168.1.2", 80, 0.1)
        assert mock_grab_banner.call_count == 2

    def test_skips_banner_grabbing_when_disabled(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner") as mock_grab_banner, \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4, grab_banners=False)

        mock_grab_banner.assert_not_called()
        assert all(d["banner"] == "" for d in devices)

    def test_attaches_risky_ports_from_find_risky_ports(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[23, 445]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert all(d["risky_ports"] == [23, 445] for d in devices)

    def test_skips_risky_port_check_when_disabled(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports") as mock_find_risky_ports, \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4, check_risky_ports=False)

        mock_find_risky_ports.assert_not_called()
        assert all(d["risky_ports"] == [] for d in devices)


class TestScanAllSubnets:
    def test_merges_devices_from_every_subnet(self):
        def fake_tcp_scan(subnet, timeout, ports, max_workers, mdns_timeout, grab_banners, check_risky_ports, excluded_networks, retries):
            return {
                "192.168.1.0/24": [
                    {"ip": "192.168.1.5", "hostname": "", "port": 80, "banner": "", "risky_ports": []}
                ],
                "10.0.0.0/24": [
                    {"ip": "10.0.0.9", "hostname": "nas.local", "port": 445, "banner": "", "risky_ports": []}
                ],
            }[subnet]

        with patch("mobile_network_scanner.tcp_scan", side_effect=fake_tcp_scan):
            devices = ms.scan_all_subnets(["192.168.1.0/24", "10.0.0.0/24"], timeout=0.1)

        assert [d["ip"] for d in devices] == ["10.0.0.9", "192.168.1.5"]

    def test_deduplicates_by_ip_across_overlapping_subnets(self):
        with patch("mobile_network_scanner.tcp_scan", return_value=[{"ip": "192.168.1.5", "hostname": "", "port": 80}]):
            devices = ms.scan_all_subnets(["192.168.1.0/24", "192.168.1.0/24"], timeout=0.1)

        assert len(devices) == 1

    def test_empty_subnet_list_returns_empty(self):
        with patch("mobile_network_scanner.tcp_scan") as mock_tcp_scan:
            assert ms.scan_all_subnets([], timeout=0.1) == []
        mock_tcp_scan.assert_not_called()


class TestDeviceIdentity:
    def test_uses_ip_as_the_identity(self):
        device = {"ip": "192.168.1.72", "hostname": "", "port": 8009}
        assert ms._device_identity(device) == "192.168.1.72"


class TestKnownDevicesPersistence:
    def test_load_returns_empty_dict_when_file_does_not_exist(self, tmp_path):
        assert ms._load_known_devices(tmp_path / "missing.json") == {}

    def test_load_returns_empty_dict_for_corrupt_json(self, tmp_path):
        path = tmp_path / "known.json"
        path.write_text("not valid json {{{", encoding="utf-8")
        assert ms._load_known_devices(path) == {}

    def test_save_then_load_round_trips(self, tmp_path):
        path = tmp_path / "nested" / "known.json"
        data = {"192.168.1.1": {"port": 80, "first_seen": "2026-01-01T00:00:00"}}

        ms._save_known_devices(data, path)

        assert ms._load_known_devices(path) == data

    def test_save_does_not_raise_on_unwritable_path(self, tmp_path):
        with patch("mobile_network_scanner.Path.mkdir", side_effect=OSError("Permission denied")):
            ms._save_known_devices({}, tmp_path / "known.json")  # Should not raise.


class TestMarkNewDevices:
    def test_first_time_seen_devices_are_all_new(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [
            {"ip": "192.168.1.1", "hostname": "router.local", "port": 80},
            {"ip": "192.168.1.72", "hostname": "", "port": 8009},
        ]

        is_new = ms._mark_new_devices(devices, known_devices_path=path)

        assert is_new == {"192.168.1.1": True, "192.168.1.72": True}

    def test_previously_seen_devices_are_not_new_on_a_later_scan(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.1", "hostname": "router.local", "port": 80}]

        ms._mark_new_devices(devices, known_devices_path=path)
        is_new = ms._mark_new_devices(devices, known_devices_path=path)

        assert is_new == {"192.168.1.1": False}

    def test_only_the_genuinely_new_device_is_flagged(self, tmp_path):
        path = tmp_path / "known.json"
        known_device = {"ip": "192.168.1.1", "hostname": "router.local", "port": 80}
        new_device = {"ip": "192.168.1.99", "hostname": "", "port": 8009}

        ms._mark_new_devices([known_device], known_devices_path=path)
        is_new = ms._mark_new_devices([known_device, new_device], known_devices_path=path)

        assert is_new == {"192.168.1.1": False, "192.168.1.99": True}

    def test_persists_device_details_and_timestamps(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.72", "hostname": "Living Room TV", "port": 8009}]

        ms._mark_new_devices(devices, known_devices_path=path)

        stored = ms._load_known_devices(path)["192.168.1.72"]
        assert stored["port"] == 8009
        assert stored["hostname"] == "Living Room TV"
        assert "first_seen" in stored
        assert "last_seen" in stored


class TestFindPortChanges:
    def test_reports_devices_whose_port_differs_from_the_registry(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}
        ms._mark_new_devices([device], known_devices_path=path)

        changed_device = dict(device, port=23)
        changes = ms._find_port_changes([changed_device], known_devices_path=path)

        assert changes == {"192.168.1.1": (80, 23)}

    def test_ignores_devices_with_an_unchanged_port(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}
        ms._mark_new_devices([device], known_devices_path=path)

        assert ms._find_port_changes([device], known_devices_path=path) == {}

    def test_a_brand_new_device_is_not_reported_as_a_port_change(self, tmp_path):
        path = tmp_path / "known.json"
        new_device = {"ip": "192.168.1.99", "hostname": "", "port": 80, "banner": "", "risky_ports": []}

        assert ms._find_port_changes([new_device], known_devices_path=path) == {}


class TestFindMissingDevices:
    def test_empty_registry_reports_nothing_missing(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.1", "hostname": "", "port": 80}]

        assert ms._find_missing_devices(devices, known_devices_path=path) == []

    def test_device_absent_from_this_scan_is_reported_missing(self, tmp_path):
        path = tmp_path / "known.json"
        router = {"ip": "192.168.1.1", "hostname": "router.local", "port": 80}
        chromecast = {"ip": "192.168.1.72", "hostname": "Living Room TV", "port": 8009}

        ms._mark_new_devices([router, chromecast], known_devices_path=path)

        missing = ms._find_missing_devices([router], known_devices_path=path)  # Chromecast unplugged.

        assert len(missing) == 1
        assert missing[0]["key"] == "192.168.1.72"
        assert missing[0]["hostname"] == "Living Room TV"

    def test_device_present_in_this_scan_is_not_reported_missing(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "hostname": "", "port": 80}

        ms._mark_new_devices([device], known_devices_path=path)

        assert ms._find_missing_devices([device], known_devices_path=path) == []

    def test_results_are_sorted_by_identity_key(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [
            {"ip": "192.168.1.9", "hostname": "", "port": 80},
            {"ip": "192.168.1.2", "hostname": "", "port": 80},
        ]

        ms._mark_new_devices(devices, known_devices_path=path)

        missing = ms._find_missing_devices([], known_devices_path=path)

        assert [entry["key"] for entry in missing] == ["192.168.1.2", "192.168.1.9"]


class TestParseExclusions:
    def test_treats_a_bare_ip_as_a_slash_32(self):
        networks = ms._parse_exclusions("192.168.1.50")
        assert networks == [ipaddress.ip_network("192.168.1.50/32")]

    def test_parses_a_cidr_range_as_is(self):
        networks = ms._parse_exclusions("192.168.1.64/28")
        assert networks == [ipaddress.ip_network("192.168.1.64/28")]

    def test_parses_multiple_comma_separated_entries(self):
        networks = ms._parse_exclusions("192.168.1.50, 192.168.1.64/28")
        assert networks == [
            ipaddress.ip_network("192.168.1.50/32"),
            ipaddress.ip_network("192.168.1.64/28"),
        ]

    def test_ignores_blank_entries(self):
        networks = ms._parse_exclusions("192.168.1.50,,")
        assert networks == [ipaddress.ip_network("192.168.1.50/32")]

    def test_raises_value_error_for_garbage_input(self):
        with pytest.raises(ValueError):
            ms._parse_exclusions("not-an-ip")


class TestIsExcluded:
    def test_true_for_an_excluded_bare_ip(self):
        networks = ms._parse_exclusions("192.168.1.50")
        assert ms._is_excluded("192.168.1.50", networks) is True

    def test_true_for_an_ip_inside_an_excluded_range(self):
        networks = ms._parse_exclusions("192.168.1.64/28")
        assert ms._is_excluded("192.168.1.70", networks) is True

    def test_false_for_an_ip_outside_every_excluded_network(self):
        networks = ms._parse_exclusions("192.168.1.50,192.168.1.64/28")
        assert ms._is_excluded("192.168.1.99", networks) is False

    def test_false_when_no_networks_are_excluded(self):
        assert ms._is_excluded("192.168.1.1", []) is False


class TestSetLabel:
    def test_sets_label_on_an_existing_device(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "hostname": "", "port": 80}
        ms._mark_new_devices([device], known_devices_path=path)

        ms._set_label("192.168.1.1", "Kitchen Echo", known_devices_path=path)

        stored = ms._load_known_devices(path)["192.168.1.1"]
        assert stored["label"] == "Kitchen Echo"

    def test_creates_a_minimal_entry_for_an_unseen_device(self, tmp_path):
        path = tmp_path / "known.json"

        ms._set_label("192.168.1.99", "Guest Phone", known_devices_path=path)

        stored = ms._load_known_devices(path)["192.168.1.99"]
        assert stored["label"] == "Guest Phone"

    def test_does_not_disturb_other_registry_fields(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "hostname": "router.local", "port": 80}
        ms._mark_new_devices([device], known_devices_path=path)

        ms._set_label("192.168.1.1", "Router", known_devices_path=path)

        stored = ms._load_known_devices(path)["192.168.1.1"]
        assert stored["hostname"] == "router.local"
        assert "first_seen" in stored


class TestRemoveLabel:
    def test_removes_an_existing_label(self, tmp_path):
        path = tmp_path / "known.json"
        ms._set_label("192.168.1.1", "Kitchen Echo", known_devices_path=path)

        ms._remove_label("192.168.1.1", known_devices_path=path)

        assert "label" not in ms._load_known_devices(path)["192.168.1.1"]

    def test_does_not_raise_for_an_unknown_device(self, tmp_path):
        path = tmp_path / "known.json"
        ms._remove_label("192.168.1.99", known_devices_path=path)  # Should not raise.

    def test_does_not_raise_for_a_device_with_no_label(self, tmp_path):
        path = tmp_path / "known.json"
        ms._mark_new_devices([{"ip": "192.168.1.1", "hostname": "", "port": 80}], known_devices_path=path)
        ms._remove_label("192.168.1.1", known_devices_path=path)  # Should not raise.


class TestLoadLabels:
    def test_returns_only_devices_with_a_label_set(self, tmp_path):
        path = tmp_path / "known.json"
        ms._mark_new_devices(
            [
                {"ip": "192.168.1.1", "hostname": "", "port": 80},
                {"ip": "192.168.1.2", "hostname": "", "port": 80},
            ],
            known_devices_path=path,
        )
        ms._set_label("192.168.1.1", "Kitchen Echo", known_devices_path=path)

        assert ms._load_labels(known_devices_path=path) == {"192.168.1.1": "Kitchen Echo"}

    def test_returns_empty_dict_when_no_labels_are_set(self, tmp_path):
        path = tmp_path / "known.json"
        ms._mark_new_devices([{"ip": "192.168.1.1", "hostname": "", "port": 80}], known_devices_path=path)

        assert ms._load_labels(known_devices_path=path) == {}


class TestDisplayHostname:
    def test_returns_bare_hostname_when_no_label_is_set(self):
        assert ms._display_hostname("router.local", "") == "router.local"

    def test_returns_label_when_no_hostname_is_set(self):
        assert ms._display_hostname("", "Kitchen Echo") == "Kitchen Echo"

    def test_combines_both_when_they_differ(self):
        assert ms._display_hostname("Chromecast-abc123.local", "Living Room TV") == \
            "Living Room TV (Chromecast-abc123.local)"

    def test_returns_just_the_label_when_they_are_identical(self):
        assert ms._display_hostname("router.local", "router.local") == "router.local"

    def test_returns_empty_string_when_neither_is_set(self):
        assert ms._display_hostname("", "") == ""


class TestDiffDevices:
    def test_no_changes_between_identical_lists(self):
        devices = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]

        result = ms.diff_devices(devices, devices)

        assert result == {"added": [], "removed": [], "changed": []}

    def test_reports_an_added_device(self):
        old = []
        new = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]

        result = ms.diff_devices(old, new)

        assert result["added"] == new
        assert result["removed"] == []
        assert result["changed"] == []

    def test_reports_a_removed_device(self):
        old = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]
        new = []

        result = ms.diff_devices(old, new)

        assert result["removed"] == old
        assert result["added"] == []

    def test_reports_a_changed_port(self):
        old = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]
        new = [{"ip": "192.168.1.5", "hostname": "phone", "port": 80, "banner": "", "risky_ports": []}]

        result = ms.diff_devices(old, new)

        assert result["changed"] == [{"key": "192.168.1.5", "ip": "192.168.1.5", "changes": {"port": (62078, 80)}}]

    def test_ip_field_itself_is_never_reported_as_a_change(self):
        # Matched by IP (the only identity this script has), so a device
        # can't actually change its "ip" field while keeping the same
        # identity - "ip" is excluded from the itemized changes anyway,
        # consistent with the function this is modeled on.
        old = [{"ip": "192.168.1.5", "hostname": "phone", "port": 80, "banner": "", "risky_ports": []}]
        new = [{"ip": "192.168.1.5", "hostname": "phone", "port": 80, "banner": "", "risky_ports": []}]

        result = ms.diff_devices(old, new)

        assert result["changed"] == []

    def test_risky_ports_change_is_reported_like_any_other_field(self):
        old = [{"ip": "192.168.1.5", "hostname": "phone", "port": 23, "banner": "", "risky_ports": []}]
        new = [{"ip": "192.168.1.5", "hostname": "phone", "port": 23, "banner": "", "risky_ports": [23]}]

        result = ms.diff_devices(old, new)

        assert result["changed"][0]["changes"] == {"risky_ports": ([], [23])}

    def test_risky_ports_is_order_insensitive(self):
        old = [{"ip": "192.168.1.5", "port": 80, "risky_ports": [23, 21]}]
        new = [{"ip": "192.168.1.5", "port": 80, "risky_ports": [21, 23]}]

        result = ms.diff_devices(old, new)

        assert result["changed"] == []

    def test_missing_risky_ports_key_normalizes_to_empty_list(self):
        old = [{"ip": "192.168.1.5", "port": 80}]
        new = [{"ip": "192.168.1.5", "port": 80, "risky_ports": []}]

        result = ms.diff_devices(old, new)

        assert result["changed"] == []


class TestPrintDiffOnly:
    def test_prints_no_changes_message_when_diff_is_empty(self, capsys):
        ms._print_diff_only({"added": [], "removed": [], "changed": []}, color=False)

        assert "No changes since the last tick." in capsys.readouterr().out

    def test_prints_added_devices(self, capsys):
        diff = {"added": [{"ip": "192.168.1.5", "hostname": "phone"}], "removed": [], "changed": []}

        ms._print_diff_only(diff, color=False)

        out = capsys.readouterr().out
        assert "1 device(s) added:" in out
        assert "192.168.1.5" in out
        assert "phone" in out

    def test_prints_removed_devices(self, capsys):
        diff = {"added": [], "removed": [{"ip": "192.168.1.5", "hostname": ""}], "changed": []}

        ms._print_diff_only(diff, color=False)

        assert "1 device(s) removed:" in capsys.readouterr().out

    def test_prints_changed_fields(self, capsys):
        diff = {"added": [], "removed": [], "changed": [{"key": "192.168.1.5", "ip": "192.168.1.5", "changes": {"port": (80, 443)}}]}

        ms._print_diff_only(diff, color=False)

        out = capsys.readouterr().out
        assert "1 device(s) changed:" in out
        assert "port: 80 -> 443" in out


class TestLoadProfile:
    def test_returns_empty_dict_when_file_does_not_exist(self, tmp_path):
        assert ms._load_profile("home", tmp_path / "missing.ini") == {}

    def test_returns_empty_dict_when_section_does_not_exist(self, tmp_path):
        path = tmp_path / "profile.ini"
        path.write_text("[work]\ntimeout = 2.0\n", encoding="utf-8")

        assert ms._load_profile("home", path) == {}

    def test_loads_a_real_section(self, tmp_path):
        path = tmp_path / "profile.ini"
        path.write_text("[home]\ntimeout = 0.8\nno-color = true\n", encoding="utf-8")

        result = ms._load_profile("home", path)

        assert result == {"timeout": "0.8", "no-color": "true"}

    def test_returns_empty_dict_on_malformed_ini(self, tmp_path):
        path = tmp_path / "profile.ini"
        path.write_text("this is not valid ini [[[", encoding="utf-8")

        assert ms._load_profile("home", path) == {}


class TestApplyProfile:
    def _make_test_parser(self):
        parser = ms.argparse.ArgumentParser()
        parser.add_argument("--timeout", type=float, default=0.5)
        parser.add_argument("--quiet", action="store_true")
        parser.add_argument("--set-label", action="append", default=[])
        parser.add_argument("--output", type=str, default=None)
        return parser

    def test_coerces_a_float_flag(self):
        parser = self._make_test_parser()
        ms._apply_profile(parser, {"timeout": "0.8"})

        args = parser.parse_args([])

        assert args.timeout == 0.8
        assert isinstance(args.timeout, float)

    def test_coerces_a_store_true_flag(self):
        parser = self._make_test_parser()
        ms._apply_profile(parser, {"quiet": "true"})

        args = parser.parse_args([])

        assert args.quiet is True

    def test_recognizes_common_boolean_spellings(self):
        for value in ("1", "true", "True", "yes", "on"):
            parser = self._make_test_parser()
            ms._apply_profile(parser, {"quiet": value})
            assert parser.parse_args([]).quiet is True, value
        for value in ("0", "false", "no", "off", ""):
            parser = self._make_test_parser()
            ms._apply_profile(parser, {"quiet": value})
            assert parser.parse_args([]).quiet is False, value

    def test_explicit_cli_flag_overrides_the_profile_value(self):
        parser = self._make_test_parser()
        ms._apply_profile(parser, {"timeout": "0.8"})

        args = parser.parse_args(["--timeout", "9.0"])

        assert args.timeout == 9.0

    def test_unknown_profile_key_is_silently_ignored(self):
        parser = self._make_test_parser()
        ms._apply_profile(parser, {"does-not-exist": "value"})  # Should not raise.

        args = parser.parse_args([])

        assert args.timeout == 0.5

    def test_append_action_flags_are_skipped_not_overwritten(self):
        parser = self._make_test_parser()
        ms._apply_profile(parser, {"set-label": "192.168.1.5=Phone"})

        args = parser.parse_args([])

        assert args.set_label == []

    def test_a_plain_string_flag_passes_through_unconverted(self):
        parser = self._make_test_parser()
        ms._apply_profile(parser, {"output": "results.json"})

        args = parser.parse_args([])

        assert args.output == "results.json"


class TestRenderPrometheusMetrics:
    def test_includes_help_and_type_lines_for_each_metric(self):
        output = ms.render_prometheus_metrics(5, 2, 1, 1700000000.0)

        assert "# HELP mobile_network_scanner_devices_total" in output
        assert "# TYPE mobile_network_scanner_devices_total gauge" in output
        assert "mobile_network_scanner_devices_total 5" in output
        assert "mobile_network_scanner_devices_new_total 2" in output
        assert "mobile_network_scanner_devices_risky_total 1" in output
        assert "mobile_network_scanner_last_scan_timestamp_seconds 1700000000.0" in output

    def test_has_no_ip_conflict_metric_at_all(self):
        # Unlike network_scanner.py's version of this function: this
        # script has no MAC address to compare against, so there's no
        # equivalent check to report a count for.
        output = ms.render_prometheus_metrics(5, 2, 1, 1700000000.0)

        assert "ip_conflicts" not in output

    def test_ends_with_a_trailing_newline(self):
        assert ms.render_prometheus_metrics(0, 0, 0, 0.0).endswith("\n")


class TestWritePrometheusMetrics:
    def test_writes_the_rendered_content_to_the_real_file(self, tmp_path):
        path = tmp_path / "metrics.prom"

        ms.write_prometheus_metrics(path, 5, 2, 1, 1700000000.0)

        content = path.read_text(encoding="utf-8")
        assert "mobile_network_scanner_devices_total 5" in content

    def test_no_leftover_tmp_file_after_a_normal_write(self, tmp_path):
        path = tmp_path / "metrics.prom"

        ms.write_prometheus_metrics(path, 1, 0, 0, 1.0)

        assert not (tmp_path / "metrics.prom.tmp").exists()
        assert path.exists()

    def test_creates_parent_directories(self, tmp_path):
        path = tmp_path / "nested" / "metrics.prom"

        ms.write_prometheus_metrics(path, 1, 0, 0, 1.0)

        assert path.exists()

    def test_does_not_raise_when_write_fails(self, tmp_path, monkeypatch):
        path = tmp_path / "metrics.prom"
        monkeypatch.setattr(ms.Path, "mkdir", lambda *a, **k: (_ for _ in ()).throw(OSError("Permission denied")))

        ms.write_prometheus_metrics(path, 1, 0, 0, 1.0)  # Should not raise.


class TestExportKnownDevices:
    def test_exports_the_current_registry(self, tmp_path):
        registry_path = tmp_path / "known.json"
        export_path = tmp_path / "backup.json"
        ms._mark_new_devices(
            [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078}],
            known_devices_path=registry_path,
        )

        count = ms.export_known_devices(export_path, known_devices_path=registry_path)

        assert count == 1
        exported = json.loads(export_path.read_text(encoding="utf-8"))
        assert "192.168.1.5" in exported

    def test_exports_an_empty_registry_as_an_empty_object(self, tmp_path):
        count = ms.export_known_devices(tmp_path / "backup.json", known_devices_path=tmp_path / "known.json")

        assert count == 0
        assert json.loads((tmp_path / "backup.json").read_text(encoding="utf-8")) == {}


class TestImportKnownDevices:
    def test_merges_into_an_empty_registry(self, tmp_path):
        backup_path = tmp_path / "backup.json"
        backup_path.write_text(json.dumps({"192.168.1.5": {"ip": "192.168.1.5"}}), encoding="utf-8")
        registry_path = tmp_path / "known.json"

        count = ms.import_known_devices(backup_path, known_devices_path=registry_path)

        assert count == 1
        assert ms._load_known_devices(registry_path) == {"192.168.1.5": {"ip": "192.168.1.5"}}

    def test_imported_entries_win_on_a_key_collision(self, tmp_path):
        registry_path = tmp_path / "known.json"
        ms._save_known_devices({"192.168.1.5": {"ip": "192.168.1.5", "label": "old"}}, registry_path)
        backup_path = tmp_path / "backup.json"
        backup_path.write_text(json.dumps({"192.168.1.5": {"ip": "192.168.1.5", "label": "new"}}), encoding="utf-8")

        ms.import_known_devices(backup_path, known_devices_path=registry_path)

        assert ms._load_known_devices(registry_path)["192.168.1.5"]["label"] == "new"

    def test_preserves_entries_not_present_in_the_import(self, tmp_path):
        registry_path = tmp_path / "known.json"
        ms._save_known_devices({"192.168.1.50": {"ip": "192.168.1.50"}}, registry_path)
        backup_path = tmp_path / "backup.json"
        backup_path.write_text(json.dumps({"192.168.1.5": {"ip": "192.168.1.5"}}), encoding="utf-8")

        ms.import_known_devices(backup_path, known_devices_path=registry_path)

        merged = ms._load_known_devices(registry_path)
        assert set(merged.keys()) == {"192.168.1.50", "192.168.1.5"}

    def test_returns_zero_and_does_not_touch_registry_when_import_file_is_empty(self, tmp_path):
        registry_path = tmp_path / "known.json"
        ms._save_known_devices({"192.168.1.5": {"ip": "192.168.1.5"}}, registry_path)
        backup_path = tmp_path / "backup.json"
        backup_path.write_text("{}", encoding="utf-8")

        count = ms.import_known_devices(backup_path, known_devices_path=registry_path)

        assert count == 0
        assert ms._load_known_devices(registry_path) == {"192.168.1.5": {"ip": "192.168.1.5"}}


class TestMqttEncodeRemainingLength:
    def test_encodes_zero_as_a_single_byte(self):
        assert ms._mqtt_encode_remaining_length(0) == bytes([0x00])

    def test_encodes_a_value_under_128_as_a_single_byte(self):
        assert ms._mqtt_encode_remaining_length(127) == bytes([0x7F])

    def test_encodes_128_as_two_bytes(self):
        # The MQTT spec's own worked example: 128 -> 0x80 0x01.
        assert ms._mqtt_encode_remaining_length(128) == bytes([0x80, 0x01])

    def test_encodes_16383_as_two_bytes(self):
        assert ms._mqtt_encode_remaining_length(16383) == bytes([0xFF, 0x7F])

    def test_encodes_16384_as_three_bytes(self):
        assert ms._mqtt_encode_remaining_length(16384) == bytes([0x80, 0x80, 0x01])

    def test_raises_on_a_negative_length(self):
        with pytest.raises(ValueError):
            ms._mqtt_encode_remaining_length(-1)

    def test_raises_when_over_the_four_byte_maximum(self):
        with pytest.raises(ValueError):
            ms._mqtt_encode_remaining_length(268435456)


class TestMqttPackets:
    def test_connect_packet_has_the_correct_fixed_header_type(self):
        packet = ms._mqtt_connect_packet("client1")

        assert packet[0] == 0x10

    def test_connect_packet_contains_the_protocol_name_and_level(self):
        packet = ms._mqtt_connect_packet("client1")

        # Fixed header (2 bytes for a short packet) + "MQTT" length-prefixed string + protocol level byte (4).
        assert packet[2:8] == b"\x00\x04MQTT"
        assert packet[8] == 4

    def test_connect_packet_sets_clean_session_flag(self):
        packet = ms._mqtt_connect_packet("client1")

        connect_flags = packet[9]
        assert connect_flags & 0x02  # Clean Session bit

    def test_connect_packet_sets_username_and_password_flags_when_given(self):
        packet = ms._mqtt_connect_packet("client1", username="bob", password="secret")

        connect_flags = packet[9]
        assert connect_flags & 0x80  # username flag
        assert connect_flags & 0x40  # password flag

    def test_connect_packet_omits_username_password_flags_when_not_given(self):
        packet = ms._mqtt_connect_packet("client1")

        connect_flags = packet[9]
        assert not (connect_flags & 0x80)
        assert not (connect_flags & 0x40)

    def test_publish_packet_has_the_correct_fixed_header_type_and_no_retain(self):
        packet = ms._mqtt_publish_packet("a/b", b"payload", retain=False)

        assert packet[0] == 0x30

    def test_publish_packet_sets_the_retain_flag(self):
        packet = ms._mqtt_publish_packet("a/b", b"payload", retain=True)

        assert packet[0] == 0x31

    def test_publish_packet_contains_the_topic_and_payload(self):
        packet = ms._mqtt_publish_packet("a/b", b"hello")

        assert b"a/b" in packet
        assert packet.endswith(b"hello")

    def test_disconnect_packet_is_the_fixed_two_byte_mqtt_constant(self):
        assert ms._MQTT_DISCONNECT_PACKET == bytes([0xE0, 0x00])

    def test_connect_packet_omits_will_flag_by_default(self):
        packet = ms._mqtt_connect_packet("client1")

        connect_flags = packet[9]
        assert not (connect_flags & 0x04)
        assert not (connect_flags & 0x20)

    def test_connect_packet_sets_will_flag_when_will_topic_given(self):
        packet = ms._mqtt_connect_packet("client1", will_topic="a/availability", will_payload=b"offline")

        connect_flags = packet[9]
        assert connect_flags & 0x04  # Will Flag

    def test_connect_packet_sets_will_retain_flag_when_requested(self):
        packet = ms._mqtt_connect_packet("client1", will_topic="a/availability", will_payload=b"offline", will_retain=True)

        connect_flags = packet[9]
        assert connect_flags & 0x20  # Will Retain

    def test_connect_packet_omits_will_retain_flag_when_not_requested(self):
        packet = ms._mqtt_connect_packet("client1", will_topic="a/availability", will_payload=b"offline", will_retain=False)

        connect_flags = packet[9]
        assert not (connect_flags & 0x20)

    def test_connect_packet_contains_the_will_topic_and_payload(self):
        packet = ms._mqtt_connect_packet("client1", will_topic="a/availability", will_payload=b"offline")

        assert b"a/availability" in packet
        assert packet.endswith(b"offline")

    def test_connect_packet_will_fields_precede_username_and_password(self):
        # Per the MQTT 3.1.1 payload ordering: Client ID, Will Topic, Will
        # Message, User Name, Password - a wrong order would silently
        # corrupt every field the broker parses after the misplaced one.
        packet = ms._mqtt_connect_packet(
            "c", username="bob", password="secret", will_topic="a/availability", will_payload=b"offline",
        )

        assert packet.index(b"a/availability") < packet.index(b"bob") < packet.index(b"secret")


class TestMqttAvailabilityTopic:
    def test_builds_the_expected_topic(self):
        assert ms.mqtt_availability_topic("homeassistant", "mobile_network_scanner") == "homeassistant/mobile_network_scanner/availability"

    def test_respects_a_custom_prefix_and_node_id(self):
        assert ms.mqtt_availability_topic("custom", "mynode") == "custom/mynode/availability"


class TestMqttSafeId:
    def test_replaces_dots_in_an_ip_address(self):
        assert ms._mqtt_safe_id("192.168.1.5") == "192_168_1_5"

    def test_leaves_alphanumerics_hyphens_and_underscores_alone(self):
        assert ms._mqtt_safe_id("already-safe_id123") == "already-safe_id123"


class TestBuildHaPresencePublishes:
    def test_builds_one_config_and_one_state_publish_per_device(self):
        devices = [{"ip": "192.168.1.5", "hostname": "phone"}]

        publishes = ms.build_ha_presence_publishes(devices)

        assert len(publishes) == 2
        topics = [p[0] for p in publishes]
        assert "homeassistant/binary_sensor/mobile_network_scanner_192_168_1_5/config" in topics
        assert "homeassistant/binary_sensor/mobile_network_scanner_192_168_1_5/state" in topics

    def test_all_publishes_are_retained(self):
        devices = [{"ip": "192.168.1.5", "hostname": "phone"}]

        publishes = ms.build_ha_presence_publishes(devices)

        assert all(retain is True for _topic, _payload, retain in publishes)

    def test_state_payload_is_on(self):
        devices = [{"ip": "192.168.1.5", "hostname": "phone"}]

        publishes = ms.build_ha_presence_publishes(devices)
        state_payload = next(payload for topic, payload, _r in publishes if topic.endswith("/state"))

        assert state_payload == b"ON"

    def test_config_payload_is_valid_json_with_presence_device_class(self):
        devices = [{"ip": "192.168.1.5", "hostname": "phone"}]

        publishes = ms.build_ha_presence_publishes(devices)
        config_payload = next(payload for topic, payload, _r in publishes if topic.endswith("/config"))
        config = json.loads(config_payload)

        assert config["device_class"] == "presence"
        assert config["unique_id"] == "mobile_network_scanner_192_168_1_5"
        assert config["state_topic"].endswith("/state")

    def test_falls_back_to_ip_when_no_hostname_or_label(self):
        devices = [{"ip": "192.168.1.5", "hostname": ""}]

        publishes = ms.build_ha_presence_publishes(devices)
        config = json.loads(next(payload for topic, payload, _r in publishes if topic.endswith("/config")))

        assert "192.168.1.5" in config["name"]

    def test_respects_a_custom_discovery_prefix_and_node_id(self):
        devices = [{"ip": "192.168.1.5"}]

        publishes = ms.build_ha_presence_publishes(devices, discovery_prefix="custom", node_id="mynode")

        assert publishes[0][0].startswith("custom/binary_sensor/mynode_")

    def test_adds_availability_topic_to_config_when_given(self):
        devices = [{"ip": "192.168.1.5"}]

        publishes = ms.build_ha_presence_publishes(devices, availability_topic="homeassistant/mobile_network_scanner/availability")
        config = json.loads(next(payload for topic, payload, _r in publishes if topic.endswith("/config")))

        assert config["availability_topic"] == "homeassistant/mobile_network_scanner/availability"

    def test_omits_availability_topic_from_config_when_not_given(self):
        devices = [{"ip": "192.168.1.5"}]

        publishes = ms.build_ha_presence_publishes(devices)
        config = json.loads(next(payload for topic, payload, _r in publishes if topic.endswith("/config")))

        assert "availability_topic" not in config


class TestBuildHaAbsencePublishes:
    def test_builds_one_off_state_publish_per_missing_device(self):
        missing = [{"key": "192.168.1.5", "last_seen": "2024-01-01T00:00:00"}]

        publishes = ms.build_ha_absence_publishes(missing)

        assert len(publishes) == 1
        topic, payload, retain = publishes[0]
        assert topic == "homeassistant/binary_sensor/mobile_network_scanner_192_168_1_5/state"
        assert payload == b"OFF"
        assert retain is True

    def test_empty_missing_list_produces_no_publishes(self):
        assert ms.build_ha_absence_publishes([]) == []


class TestPublishMqtt:
    """Real, unmocked TCP: a genuine fake MQTT broker over real loopback
    sockets, verifying the actual wire bytes sent by publish_mqtt()."""

    def _run_fake_broker(self, expect_packets=1, respond_ok=True):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        received = {"data": b"", "connect": b""}

        def serve():
            conn, _addr = server.accept()
            received["connect"] = conn.recv(4096)  # CONNECT
            if respond_ok:
                conn.sendall(bytes([0x20, 0x02, 0x00, 0x00]))
            else:
                conn.sendall(bytes([0x20, 0x02, 0x00, 0x05]))  # a rejection code
            conn.settimeout(1.0)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    received["data"] += chunk
            except socket.timeout:
                pass
            conn.close()
            server.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        return port, thread, received

    def test_publishes_are_actually_sent_over_a_real_socket(self):
        port, thread, received = self._run_fake_broker()

        ms.publish_mqtt("127.0.0.1", port, "test-client", [("a/b", b"hello", False)])
        thread.join(timeout=2)

        assert b"a/b" in received["data"]
        assert b"hello" in received["data"]

    def test_disconnect_is_sent_after_publishes(self):
        port, thread, received = self._run_fake_broker()

        ms.publish_mqtt("127.0.0.1", port, "test-client", [("a/b", b"hello", False)])
        thread.join(timeout=2)

        assert received["data"].endswith(bytes([0xE0, 0x00]))

    def test_raises_runtime_error_when_broker_rejects_the_connection(self):
        port, thread, _received = self._run_fake_broker(respond_ok=False)

        with pytest.raises(RuntimeError, match="rejected"):
            ms.publish_mqtt("127.0.0.1", port, "test-client", [("a/b", b"hello", False)])
        thread.join(timeout=2)

    def test_raises_oserror_when_nothing_is_listening(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()  # Bound-then-closed port - nothing listening there now.

        with pytest.raises(OSError):
            ms.publish_mqtt("127.0.0.1", port, "test-client", [], timeout=1.0)

    def test_availability_topic_sets_will_bits_in_connect(self):
        port, thread, received = self._run_fake_broker()

        ms.publish_mqtt(
            "127.0.0.1", port, "test-client", [("a/b", b"hello", False)],
            availability_topic="homeassistant/test-client/availability",
        )
        thread.join(timeout=2)

        assert b"homeassistant/test-client/availability" in received["connect"]
        assert received["connect"].endswith(b"offline")  # the will payload
        connect_flags = received["connect"][9]
        assert connect_flags & 0x04  # Will Flag
        assert connect_flags & 0x20  # Will Retain

    def test_availability_topic_is_published_online_before_other_publishes(self):
        port, thread, received = self._run_fake_broker()

        ms.publish_mqtt(
            "127.0.0.1", port, "test-client", [("a/b", b"hello", False)],
            availability_topic="homeassistant/test-client/availability",
        )
        thread.join(timeout=2)

        online_index = received["data"].index(b"online")
        hello_index = received["data"].index(b"hello")
        assert online_index < hello_index

    def test_no_availability_topic_means_no_will_bits(self):
        port, thread, received = self._run_fake_broker()

        ms.publish_mqtt("127.0.0.1", port, "test-client", [("a/b", b"hello", False)])
        thread.join(timeout=2)

        connect_flags = received["connect"][9]
        assert not (connect_flags & 0x04)
        assert b"availability" not in received["data"]
        assert b"online" not in received["data"]


class TestPublishMqttTls:
    """Socket/SSL wiring verified with mocks (rather than a real cert/handshake,
    which would need shelling out to openssl or a new cryptography dependency
    just for tests) - a real TLS handshake against a real self-signed
    certificate over a real loopback socket *was* manually verified during
    development; see TODO.md for why that isn't part of the committed suite."""

    def _make_fake_raw_socket(self, connack=bytes([0x20, 0x02, 0x00, 0x00])):
        fake_raw = MagicMock()
        fake_wrapped = MagicMock()
        fake_wrapped.recv.return_value = connack
        return fake_raw, fake_wrapped

    def test_use_tls_wraps_the_socket_with_an_ssl_context(self):
        fake_raw, fake_wrapped = self._make_fake_raw_socket()
        fake_context = MagicMock()
        fake_context.wrap_socket.return_value = fake_wrapped

        with patch.object(ms.socket, "create_connection", return_value=fake_raw), \
             patch.object(ms.ssl, "create_default_context", return_value=fake_context) as mock_ctx:
            ms.publish_mqtt("broker.example", 8883, "client", [], use_tls=True)

        mock_ctx.assert_called_once()
        fake_context.wrap_socket.assert_called_once_with(fake_raw, server_hostname="broker.example")
        fake_wrapped.sendall.assert_called()  # the wrapped socket, not the raw one, does the actual talking

    def test_plain_connection_never_touches_ssl(self):
        fake_raw, _fake_wrapped = self._make_fake_raw_socket()
        fake_raw.recv.return_value = bytes([0x20, 0x02, 0x00, 0x00])

        with patch.object(ms.socket, "create_connection", return_value=fake_raw), \
             patch.object(ms.ssl, "create_default_context") as mock_ctx:
            ms.publish_mqtt("broker.example", 1883, "client", [], use_tls=False)

        mock_ctx.assert_not_called()

    def test_insecure_tls_disables_hostname_and_certificate_verification(self):
        fake_raw, fake_wrapped = self._make_fake_raw_socket()
        fake_context = MagicMock()
        fake_context.wrap_socket.return_value = fake_wrapped

        with patch.object(ms.socket, "create_connection", return_value=fake_raw), \
             patch.object(ms.ssl, "create_default_context", return_value=fake_context):
            ms.publish_mqtt("broker.example", 8883, "client", [], use_tls=True, insecure_tls=True)

        assert fake_context.check_hostname is False
        assert fake_context.verify_mode == ms.ssl.CERT_NONE

    def test_secure_tls_leaves_default_verification_alone(self):
        fake_raw, fake_wrapped = self._make_fake_raw_socket()
        fake_context = MagicMock()
        fake_context.wrap_socket.return_value = fake_wrapped
        fake_context.check_hostname = True  # ssl.create_default_context()'s own real default

        with patch.object(ms.socket, "create_connection", return_value=fake_raw), \
             patch.object(ms.ssl, "create_default_context", return_value=fake_context):
            ms.publish_mqtt("broker.example", 8883, "client", [], use_tls=True, insecure_tls=False)

        assert fake_context.check_hostname is True

    def test_closes_the_wrapped_socket_not_the_raw_one(self):
        fake_raw, fake_wrapped = self._make_fake_raw_socket()
        fake_context = MagicMock()
        fake_context.wrap_socket.return_value = fake_wrapped

        with patch.object(ms.socket, "create_connection", return_value=fake_raw), \
             patch.object(ms.ssl, "create_default_context", return_value=fake_context):
            ms.publish_mqtt("broker.example", 8883, "client", [], use_tls=True)

        fake_wrapped.close.assert_called_once()


class TestResolveMqttPassword:
    def test_explicit_password_wins_over_everything(self, tmp_path, monkeypatch):
        password_file = tmp_path / "pw.txt"
        password_file.write_text("from-file\n", encoding="utf-8")
        monkeypatch.setenv("MQTT_PASSWORD", "from-env")

        assert ms._resolve_mqtt_password("from-flag", str(password_file)) == "from-flag"

    def test_falls_back_to_password_file_when_no_explicit_password(self, tmp_path, monkeypatch):
        password_file = tmp_path / "pw.txt"
        password_file.write_text("from-file\n", encoding="utf-8")
        monkeypatch.setenv("MQTT_PASSWORD", "from-env")

        assert ms._resolve_mqtt_password(None, str(password_file)) == "from-file"

    def test_password_file_contents_are_stripped(self, tmp_path):
        password_file = tmp_path / "pw.txt"
        password_file.write_text("  from-file  \n", encoding="utf-8")

        assert ms._resolve_mqtt_password(None, str(password_file)) == "from-file"

    def test_falls_back_to_env_var_when_neither_flag_nor_file_given(self, monkeypatch):
        monkeypatch.setenv("MQTT_PASSWORD", "from-env")

        assert ms._resolve_mqtt_password(None, None) == "from-env"

    def test_returns_none_when_nothing_is_configured(self, monkeypatch):
        monkeypatch.delenv("MQTT_PASSWORD", raising=False)

        assert ms._resolve_mqtt_password(None, None) is None

    def test_raises_when_password_file_does_not_exist(self, tmp_path):
        with pytest.raises(OSError):
            ms._resolve_mqtt_password(None, str(tmp_path / "missing.txt"))


class TestMainDiffOnly:
    """End-to-end --watch --diff-only: two ticks, mocking only the scan
    itself and time.sleep (to end the loop) - everything else (arg
    parsing, the registry, diff_devices(), printing) runs for real."""

    def test_first_tick_prints_full_table_second_tick_prints_diff_only(self, tmp_path, monkeypatch, capsys):
        known_path = tmp_path / "known.json"
        tick1 = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]
        tick2 = [{"ip": "192.168.1.5", "hostname": "phone", "port": 80, "banner": "", "risky_ports": []}]

        monkeypatch.setattr(sys, "argv", ["mobile_network_scanner.py", "192.168.1.0/24", "--watch", "1", "--diff-only", "--no-color"])
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", side_effect=[tick1, tick2]), \
             patch.object(ms.time, "sleep", side_effect=[None, KeyboardInterrupt]):
            ms.main()

        out = capsys.readouterr().out
        assert "IP Address" in out  # First tick: the full table header.
        assert "1 device(s) changed:" in out  # Second tick: diff-only output.
        assert "port: 62078 -> 80" in out

    def test_no_previous_tick_means_no_diff_only_output_on_the_very_first_tick(self, tmp_path, monkeypatch, capsys):
        known_path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]

        monkeypatch.setattr(sys, "argv", ["mobile_network_scanner.py", "192.168.1.0/24", "--diff-only", "--no-color"])
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=devices):
            ms.main()

        out = capsys.readouterr().out
        assert "IP Address" in out
        assert "No changes since the last tick." not in out


class TestMainProfile:
    def test_profile_values_are_used_when_not_overridden_on_the_command_line(self, tmp_path, monkeypatch):
        profile_path = tmp_path / "profile.ini"
        profile_path.write_text("[home]\ntimeout = 1.5\n", encoding="utf-8")
        known_path = tmp_path / "known.json"

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--profile", "home", "--profile-file", str(profile_path), "--no-color", "--quiet"],
        )
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=[]) as mock_scan:
            ms.main()

        assert mock_scan.call_args.kwargs["timeout"] == 1.5

    def test_explicit_cli_timeout_overrides_the_profile(self, tmp_path, monkeypatch):
        profile_path = tmp_path / "profile.ini"
        profile_path.write_text("[home]\ntimeout = 1.5\n", encoding="utf-8")
        known_path = tmp_path / "known.json"

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--profile", "home", "--profile-file", str(profile_path),
             "--timeout", "2.0", "--no-color", "--quiet"],
        )
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=[]) as mock_scan:
            ms.main()

        assert mock_scan.call_args.kwargs["timeout"] == 2.0

    def test_unknown_profile_name_is_a_usage_error(self, tmp_path, monkeypatch, capsys):
        profile_path = tmp_path / "profile.ini"
        profile_path.write_text("[home]\ntimeout = 1.5\n", encoding="utf-8")

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "--profile", "office", "--profile-file", str(profile_path), "--doctor"],
        )
        with pytest.raises(SystemExit) as excinfo:
            ms.main()

        assert excinfo.value.code == 2
        assert "not found" in capsys.readouterr().err


class TestMainMetricsFile:
    def test_writes_metrics_after_a_real_scan(self, tmp_path, monkeypatch):
        known_path = tmp_path / "known.json"
        metrics_path = tmp_path / "metrics.prom"
        devices = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--metrics-file", str(metrics_path), "--no-color", "--quiet"],
        )
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=devices):
            ms.main()

        content = metrics_path.read_text(encoding="utf-8")
        assert "mobile_network_scanner_devices_total 1" in content

    def test_writes_zeroed_metrics_on_an_empty_scan(self, tmp_path, monkeypatch):
        known_path = tmp_path / "known.json"
        metrics_path = tmp_path / "metrics.prom"

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--metrics-file", str(metrics_path), "--no-color", "--quiet"],
        )
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=[]):
            ms.main()

        content = metrics_path.read_text(encoding="utf-8")
        assert "mobile_network_scanner_devices_total 0" in content


class TestMainExportImportKnownDevices:
    def test_export_flag_exits_zero_after_writing(self, tmp_path, monkeypatch, capsys):
        known_path = tmp_path / "known.json"
        ms._mark_new_devices([{"ip": "192.168.1.5"}], known_devices_path=known_path)
        export_path = tmp_path / "backup.json"

        monkeypatch.setattr(sys, "argv", ["mobile_network_scanner.py", "--export-known-devices", str(export_path)])
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path):
            with pytest.raises(SystemExit) as excinfo:
                ms.main()

        assert excinfo.value.code == 0
        assert export_path.exists()
        assert "Exported 1" in capsys.readouterr().out

    def test_import_flag_exits_zero_after_merging(self, tmp_path, monkeypatch, capsys):
        known_path = tmp_path / "known.json"
        backup_path = tmp_path / "backup.json"
        backup_path.write_text(json.dumps({"192.168.1.5": {"ip": "192.168.1.5"}}), encoding="utf-8")

        monkeypatch.setattr(sys, "argv", ["mobile_network_scanner.py", "--import-known-devices", str(backup_path)])
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path):
            with pytest.raises(SystemExit) as excinfo:
                ms.main()

        assert excinfo.value.code == 0
        assert ms._load_known_devices(known_path) == {"192.168.1.5": {"ip": "192.168.1.5"}}
        assert "Imported 1" in capsys.readouterr().out


class TestMainMqtt:
    def test_publish_mqtt_is_called_with_presence_and_absence_publishes(self, tmp_path, monkeypatch):
        known_path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--mqtt-host", "broker.local", "--no-color", "--quiet"],
        )
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=devices), \
             patch.object(ms, "publish_mqtt") as mock_publish:
            ms.main()

        assert mock_publish.called
        host, port, client_id, publishes = mock_publish.call_args.args
        assert host == "broker.local"
        assert port == 1883
        assert any(topic.endswith("/state") and payload == b"ON" for topic, payload, _r in publishes)

    def test_a_failed_mqtt_publish_warns_but_does_not_crash_the_scan(self, tmp_path, monkeypatch, capsys):
        known_path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--mqtt-host", "broker.local", "--no-color", "--quiet"],
        )
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=devices), \
             patch.object(ms, "publish_mqtt", side_effect=OSError("connection refused")):
            ms.main()  # Should not raise.

    def test_default_publish_includes_an_availability_topic(self, tmp_path, monkeypatch):
        known_path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--mqtt-host", "broker.local", "--no-color", "--quiet"],
        )
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=devices), \
             patch.object(ms, "publish_mqtt") as mock_publish:
            ms.main()

        assert mock_publish.call_args.kwargs["availability_topic"] == "homeassistant/mobile_network_scanner/availability"

    def test_mqtt_no_availability_flag_disables_it(self, tmp_path, monkeypatch):
        known_path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--mqtt-host", "broker.local", "--mqtt-no-availability", "--no-color", "--quiet"],
        )
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=devices), \
             patch.object(ms, "publish_mqtt") as mock_publish:
            ms.main()

        assert mock_publish.call_args.kwargs["availability_topic"] is None
        config = json.loads(next(p for t, p, _r in mock_publish.call_args.args[3] if t.endswith("/config")))
        assert "availability_topic" not in config

    def test_mqtt_tls_flags_are_passed_through(self, tmp_path, monkeypatch):
        known_path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--mqtt-host", "broker.local", "--mqtt-tls",
             "--mqtt-insecure-tls", "--no-color", "--quiet"],
        )
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=devices), \
             patch.object(ms, "publish_mqtt") as mock_publish:
            ms.main()

        assert mock_publish.call_args.kwargs["use_tls"] is True
        assert mock_publish.call_args.kwargs["insecure_tls"] is True

    def test_mqtt_password_file_is_used_when_no_explicit_password(self, tmp_path, monkeypatch):
        known_path = tmp_path / "known.json"
        password_file = tmp_path / "pw.txt"
        password_file.write_text("secret-from-file\n", encoding="utf-8")
        devices = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--mqtt-host", "broker.local",
             "--mqtt-password-file", str(password_file), "--no-color", "--quiet"],
        )
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=devices), \
             patch.object(ms, "publish_mqtt") as mock_publish:
            ms.main()

        assert mock_publish.call_args.kwargs["password"] == "secret-from-file"

    def test_explicit_mqtt_password_overrides_password_file(self, tmp_path, monkeypatch):
        known_path = tmp_path / "known.json"
        password_file = tmp_path / "pw.txt"
        password_file.write_text("secret-from-file\n", encoding="utf-8")
        devices = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--mqtt-host", "broker.local", "--mqtt-password", "explicit-secret",
             "--mqtt-password-file", str(password_file), "--no-color", "--quiet"],
        )
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=devices), \
             patch.object(ms, "publish_mqtt") as mock_publish:
            ms.main()

        assert mock_publish.call_args.kwargs["password"] == "explicit-secret"

    def test_mqtt_password_env_var_is_used_as_a_last_resort(self, tmp_path, monkeypatch):
        known_path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.5", "hostname": "phone", "port": 62078, "banner": "", "risky_ports": []}]
        monkeypatch.setenv("MQTT_PASSWORD", "secret-from-env")

        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--mqtt-host", "broker.local", "--no-color", "--quiet"],
        )
        with patch.object(ms, "_KNOWN_DEVICES_PATH", known_path), \
             patch.object(ms, "scan_all_subnets", return_value=devices), \
             patch.object(ms, "publish_mqtt") as mock_publish:
            ms.main()

        assert mock_publish.call_args.kwargs["password"] == "secret-from-env"

    def test_missing_mqtt_password_file_is_a_usage_error(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(
            sys, "argv",
            ["mobile_network_scanner.py", "192.168.1.0/24", "--mqtt-host", "broker.local",
             "--mqtt-password-file", str(tmp_path / "missing.txt"), "--doctor"],
        )
        with pytest.raises(SystemExit) as excinfo:
            ms.main()

        assert excinfo.value.code == 2
        assert "mqtt-password-file" in capsys.readouterr().err
