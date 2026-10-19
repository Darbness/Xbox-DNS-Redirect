#!/usr/bin/env python3
"""End-to-end tests for app.py -- real sockets, real TLS, real log files.

Run:  python test_app_full.py      (no privileged ports, nothing left running)
"""
import json
import os
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app  # noqa: E402
from dnslib import DNSRecord, QTYPE, RR, A, DNSHeader  # noqa: E402

TEST_IP = "192.0.2.77"          # TEST-NET-1: never a real address
TMP = tempfile.mkdtemp(prefix="allinone-test-")


def start_dns(cfg):
    u = app.DnsUdpServer("127.0.0.1", 0, cfg)
    u.start()
    t = app.DnsTcpServer(("127.0.0.1", 0), app.DnsTcpHandler)
    t.dns_cfg = cfg
    threading.Thread(target=t.serve_forever, daemon=True).start()
    return u, t, u.sock.getsockname()[1], t.server_address[1]


def udp_query(port, name, qtype="A", timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(DNSRecord.question(name, qtype).pack(), ("127.0.0.1", port))
    data, _ = s.recvfrom(4096)
    s.close()
    return DNSRecord.parse(data)


def tcp_query(port, name, qtype="A"):
    q = DNSRecord.question(name, qtype).pack()
    s = socket.create_connection(("127.0.0.1", port), 3)
    s.sendall(struct.pack(">H", len(q)) + q)
    n = struct.unpack(">H", recvn(s, 2))[0]
    data = recvn(s, n)
    s.close()
    return DNSRecord.parse(data)


def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            break
        buf += c
    return buf


def http_raw(port, path="/", host=None, method="GET", body=None, timeout=4):
    """No redirect following: needed to assert on 302 responses."""
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Host": host} if host else {}
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    out = (r.status, r.read(), dict(r.getheaders()))
    c.close()
    return out


def http_get(url, host=None, timeout=4):
    req = urllib.request.Request(url)
    if host:
        req.add_unredirected_header("Host", host)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


class Upstream(threading.Thread):
    """Tiny stand-in for a real resolver: answers 198.51.100.9 for everything."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.queries = []

    def run(self):
        while True:
            try:
                raw, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            q = DNSRecord.parse(raw)
            self.queries.append(str(q.q.qname))
            r = DNSRecord(DNSHeader(id=q.header.id, qr=1, aa=1), q=q.q)
            r.add_answer(RR(q.q.qname, QTYPE.A, rdata=A("198.51.100.9"), ttl=60))
            self.sock.sendto(r.pack(), addr)


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.LOG = app.Log(os.path.join(TMP, "log.txt"))
        cls.webroot = os.path.join(TMP, "web")
        os.makedirs(cls.webroot, exist_ok=True)
        with open(os.path.join(cls.webroot, "harness.html"), "w") as f:
            f.write("<h1>harness</h1>")
        # nested fixtures for the directory-listing tests (binary: exact bytes)
        os.makedirs(os.path.join(cls.webroot, "subdir", "sub-sub"), exist_ok=True)
        os.makedirs(os.path.join(cls.webroot, "hasindex"), exist_ok=True)
        with open(os.path.join(cls.webroot, "subdir", "inside.txt"), "wb") as f:
            f.write(b"hello-from-subdir\n")
        with open(os.path.join(cls.webroot, "subdir", "sub-sub", "deep.txt"), "wb") as f:
            f.write(b"deep\n")
        with open(os.path.join(cls.webroot, "hasindex", "index.html"), "wb") as f:
            f.write(b"<h1>INDEX</h1>\n")

    # ---------------- DNS ----------------
    def test_dns_reply_contract(self):
        r = app.dns_reply(DNSRecord.question("example.test"), TEST_IP, None)
        self.assertEqual(str(r.rr[0].rdata), TEST_IP)
        self.assertEqual(r.rr[0].ttl, 0)
        self.assertEqual(r.header.qr, 1)

    def test_dns_reply_aaaa_is_nodata(self):
        r = app.dns_reply(DNSRecord.question("example.test", "AAAA"), TEST_IP, None)
        self.assertEqual(len(r.rr), 0)
        self.assertEqual(r.header.rcode, 0)
        self.assertTrue(r.auth)          # SOA makes the negative answer well formed

    def test_dns_udp_redirects_everything(self):
        cfg = app.DnsConfig(TEST_IP)
        u, t, up, tp = start_dns(cfg)
        try:
            for name in ("www.microsoft.com", "example.test", "a.b.c.d.e.f"):
                r = udp_query(up, name)
                self.assertEqual(str(r.rr[0].rdata), TEST_IP, name)
                self.assertEqual(r.rr[0].ttl, 0)
            r6 = udp_query(up, "www.microsoft.com", "AAAA")
            self.assertEqual(len(r6.rr), 0)
        finally:
            u.stop(); t.shutdown()

    def test_dns_tcp_same_answer(self):
        cfg = app.DnsConfig(TEST_IP)
        u, t, up, tp = start_dns(cfg)
        try:
            r = tcp_query(tp, "tcp.example")
            self.assertEqual(str(r.rr[0].rdata), TEST_IP)
        finally:
            u.stop(); t.shutdown()

    def test_udp_survives_icmp_reset(self):
        """Regression: on Windows a reply to a client that already closed its
        socket makes the NEXT recvfrom() fail with WSAECONNRESET, which used to
        kill the DNS thread -- the port stayed bound and nothing answered again.
        Stub resolvers do exactly this on every query, so the listener must
        survive it."""
        if os.name == "nt":
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                self.assertTrue(app.disable_udp_conn_reset(probe),
                                "SIO_UDP_CONNRESET could not be set; UDP would die on "
                                "the first ICMP port-unreachable")
            finally:
                probe.close()
        cfg = app.DnsConfig(TEST_IP)
        u, t, up, tp = start_dns(cfg)
        try:
            # fire-and-close: each reply lands on a dead port -> ICMP unreachable
            for i in range(12):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(DNSRecord.question(f"gone{i}.example").pack(), ("127.0.0.1", up))
                s.close()
            time.sleep(0.8)
            r = udp_query(up, "still-here.example", timeout=5)
            self.assertEqual(str(r.rr[0].rdata), TEST_IP,
                             "DNS stopped answering after clients closed early")
            self.assertFalse(u.stop_flag.is_set(), "DNS udp thread gave up")
            import threading as _t
            self.assertTrue(any(x.name.startswith("dns-udp") and x.is_alive()
                                for x in _t.enumerate()), "DNS udp thread is not alive")
            r2 = udp_query(up, "second-check.example", timeout=5)
            self.assertEqual(str(r2.rr[0].rdata), TEST_IP)
        finally:
            u.stop(); t.shutdown()

    def test_dns_survives_malformed_packets(self):
        cfg = app.DnsConfig(TEST_IP)
        u, t, up, tp = start_dns(cfg)
        try:
            g = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for junk in (b"\x00" * 12 + b"\xff\xff\xff", b"\x12\x34\x01\x00\x00\x01",
                         b"", b"\xff" * 600, os.urandom(40)):
                g.sendto(junk, ("127.0.0.1", up))
            g.close()
            time.sleep(0.4)
            self.assertEqual(str(udp_query(up, "after-junk.example").rr[0].rdata), TEST_IP)
        finally:
            u.stop(); t.shutdown()

    def test_http_client_disconnect_is_not_a_traceback(self):
        """A client that drops mid-request must produce a log line, not stderr."""
        srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="http",
                                webroot="", mode="page", page="P", cfg_ip=TEST_IP)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            s = socket.create_connection(("127.0.0.1", port), 3)
            s.sendall(b"GET /half HTTP/1.1\r\nHost: x.example\r\n")   # no terminator
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack("hh", 1, 0))                     # hard RST
            s.close()
            time.sleep(0.5)
            self.assertTrue(any("dropped mid-request" in e["text"]
                                or "Res" in e["text"] for e in app.LOG.query(0, 200, "sys")),
                            "client disconnect was not recorded as an event")
            r = udp_query  # keep linters quiet about unused import order
            self.assertEqual(http_raw(port, "/after-reset", host="x.example")[0], 200)
        finally:
            srv.shutdown()

    def test_dns_bypass_uses_real_upstream(self):
        ups = Upstream(); ups.start()
        cfg = app.DnsConfig(TEST_IP, upstreams=[f"127.0.0.1:{ups.port}"],
                            bypass=["real.example"], forward_all=False)
        u, t, up, tp = start_dns(cfg)
        try:
            r = udp_query(up, "login.real.example")
            self.assertEqual(str(r.rr[0].rdata), "198.51.100.9")   # relayed for real
            self.assertEqual(str(r.rr[0].rdata), "198.51.100.9")
            r2 = udp_query(up, "ads.other.example")
            self.assertEqual(str(r2.rr[0].rdata), TEST_IP)          # hijacked
            self.assertIn("login.real.example.", ups.queries)
        finally:
            u.stop(); t.shutdown()

    def test_dns_forward_all_relays(self):
        ups = Upstream(); ups.start()
        cfg = app.DnsConfig(TEST_IP, upstreams=[f"127.0.0.1:{ups.port}"], forward_all=True)
        u, t, up, tp = start_dns(cfg)
        try:
            self.assertEqual(str(udp_query(up, "anything.example").rr[0].rdata), "198.51.100.9")
        finally:
            u.stop(); t.shutdown()

    def test_dns_upstream_down_servfails(self):
        cfg = app.DnsConfig(TEST_IP, upstreams=["127.0.0.1:9"], bypass=["x.example"])
        u, t, up, tp = start_dns(cfg)
        try:
            r = udp_query(up, "x.example", timeout=6)
            self.assertEqual(r.header.rcode, 2)     # SERVFAIL
            r2 = udp_query(up, "y.example")
            self.assertEqual(str(r2.rr[0].rdata), TEST_IP)
        finally:
            u.stop(); t.shutdown()

    # ---------------- HTTP ----------------
    def test_http_capture_and_logging(self):
        srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="http",
                                webroot=self.webroot, mode="auto", page="PAGE",
                                cfg_ip=TEST_IP)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            st, body, hdrs = http_get(f"http://127.0.0.1:{port}/harness.html",
                                      host="evil.example:80")
            self.assertEqual(st, 200)
            self.assertEqual(body, b"<h1>harness</h1>")
            st, body, _ = http_get(f"http://127.0.0.1:{port}/", host="evil.example")
            self.assertEqual(st, 200)
            self.assertIn(b"harness.html", body)            # directory listing
            st, _, hdrs = http_raw(port, "/nope", host="evil.example")
            self.assertEqual(st, 302)
            # our own address, same scheme -- not the requested host, not https
            self.assertEqual(hdrs["Location"], f"http://{TEST_IP}:{port}/nope")
            self.assertNotIn("evil.example", hdrs["Location"])
        finally:
            srv.shutdown()
        ent = app.LOG.query(0, 500, "http")
        self.assertTrue(any(e["meta"].get("host") == "evil.example" and
                            e["meta"].get("path") == "/harness.html" for e in ent),
                        "GET /harness.html was not logged with its Host")

    def test_http_redirect_points_at_us_over_http_not_https(self):
        """The redirect must go to OUR address (a cached answer, DoH lookup or
        hardcoded IP would otherwise take the device to the real server) and must
        stay on http (a device that doesn't trust our cert gets nothing from an
        https redirect)."""
        srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="http",
                                webroot="", mode="auto", page="P", cfg_ip=TEST_IP,
                                redirect_template="http://{ip}:{port}{path}")
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            st, _, hdrs = http_raw(port, "/ncsi.txt", host="www.msftncsi.com")
            self.assertEqual(st, 302)
            loc = hdrs["Location"]
            self.assertNotIn("msftncsi.com", loc)
            self.assertFalse(loc.startswith("https://"), loc)
            self.assertEqual(loc, f"http://{TEST_IP}:{port}/ncsi.txt")
            st, _, hdrs = http_raw(port, "/xboxlive/login?x=1", host="xncsi.xboxlive.com")
            self.assertEqual(hdrs["Location"], f"http://{TEST_IP}:{port}/xboxlive/login?x=1")
        finally:
            srv.shutdown()

    def test_redirect_chain_lands_on_us_over_http_without_looping(self):
        """Follow the 302 the way the console does: the follow-up arrives with
        Host = our IP and must be answered (200), not redirected again forever."""
        srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="http",
                                webroot="", mode="auto", page="LANDING PAGE",
                                cfg_ip="127.0.0.1")
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            st, _, hdrs = http_raw(port, "/ncsi.txt", host="www.msftncsi.com")
            self.assertEqual(st, 302)
            loc = hdrs["Location"]
            self.assertEqual(loc, f"http://127.0.0.1:{port}/ncsi.txt")
            # step 2: exactly what a client does with that Location
            st2, body2, _ = http_raw(port, "/ncsi.txt", host=f"127.0.0.1:{port}")
            self.assertEqual(st2, 200, "redirect target redirected again (loop)")
            self.assertIn(b"LANDING PAGE", body2,
                          "nothing was invented for a path with no file on disk")
            # a non-probe path on our own address must serve, never bounce
            st3, body3, _ = http_raw(port, "/anything-else", host=f"127.0.0.1:{port}")
            self.assertEqual(st3, 200)
            self.assertIn(b"LANDING PAGE", body3)
        finally:
            srv.shutdown()

    def test_webroot_file_is_served_verbatim_for_any_host(self):
        """Whatever the device asks for, if that path exists under --webroot we
        return those exact bytes -- no redirect, no invented content.  Same file,
        three different Host values (real name, our IP, IP:port)."""
        root = os.path.join(TMP, "probe-web")
        os.makedirs(root, exist_ok=True)
        payload = b"Microsoft NCSI\n"          # the user's file, not ours
        with open(os.path.join(root, "ncsi.txt"), "wb") as f:
            f.write(payload)
        srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="http",
                                webroot=root, mode="auto", page="PAGE", cfg_ip="127.0.0.1")
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            for host in ("www.msftncsi.com", "xncsi.xboxlive.com", "192.168.1.146",
                         f"127.0.0.1:{port}", "anything.at.all"):
                st, body, _ = http_raw(port, "/ncsi.txt", host=host)
                self.assertEqual(st, 200, host)
                self.assertEqual(body, payload, host)
            # a path with no file still redirects to us (never invented)
            st, _, hdrs = http_raw(port, "/not-a-file", host="www.msftncsi.com")
            self.assertEqual(st, 302)
            self.assertTrue(hdrs["Location"].startswith("http://127.0.0.1"))
        finally:
            srv.shutdown()

    def test_http_serve_mode_404(self):
        srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="http",
                                webroot=self.webroot, mode="serve", page="PAGE",
                                cfg_ip=TEST_IP)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            self.assertEqual(http_get(f"http://127.0.0.1:{port}/gone")[0], 404)
        finally:
            srv.shutdown()

    def test_http_post_body_logged(self):
        srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="http",
                                webroot="", mode="page", page="ok", cfg_ip=TEST_IP)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/submit",
                                         data=b"xid=42&tag=hello", method="POST")
            with urllib.request.urlopen(req, timeout=4) as r:
                self.assertEqual(r.status, 200)
        finally:
            srv.shutdown()
        ent = app.LOG.query(0, 500, "http")
        self.assertTrue(any("xid=42" in (e["meta"].get("body") or "") for e in ent))

    def test_http_traversal_blocked(self):
        srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="http",
                                webroot=self.webroot, mode="serve", page="P",
                                cfg_ip=TEST_IP)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            st, _, _ = http_get(f"http://127.0.0.1:{port}/../app.py")
            self.assertIn(st, (403, 404))
        finally:
            srv.shutdown()

    # ---------------- HTTPS ----------------
    def test_https_tls_with_our_cert_as_ca(self):
        cert, key = app.ensure_cert(os.path.join(TMP, "c.crt"),
                                    os.path.join(TMP, "c.key"),
                                    force=True, log=lambda m: None)
        srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="https",
                                webroot=self.webroot, mode="page", page="SECURE",
                                cfg_ip=TEST_IP, tls=(cert, key))
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(cert)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection(("127.0.0.1", port), 5) as raw:
                with ctx.wrap_socket(raw, server_hostname="www.xboxlive.com") as tls:
                    self.assertEqual(tls.version() in ("TLSv1.2", "TLSv1.3"), True)
                    tls.sendall(b"GET /secure?x=1 HTTP/1.1\r\nHost: www.xboxlive.com\r\n"
                                b"Connection: close\r\n\r\n")
                    data = recvn(tls, 4096)
            self.assertIn(b"200", data.split(b"\r\n")[0])
            self.assertIn(b"SECURE", data)
            ent = app.LOG.query(0, 500, "https")
            self.assertTrue(any(e["meta"].get("sni") == "www.xboxlive.com" for e in ent),
                            "SNI was not captured on the HTTPS request")
        finally:
            srv.shutdown()

    def test_https_wrong_hostname_is_rejected_by_client(self):
        """Proves the SAN list really drives validation (not a blanket 'anything' cert)."""
        cert, key = app.ensure_cert(os.path.join(TMP, "c.crt"),
                                    os.path.join(TMP, "c.key"), log=lambda m: None)
        srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="https",
                                webroot="", mode="page", page="S", cfg_ip=TEST_IP,
                                tls=(cert, key))
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(cert)
            ctx.check_hostname = True
            with socket.create_connection(("127.0.0.1", port), 5) as raw:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    ctx.wrap_socket(raw, server_hostname="totally.unlisted-name-xyz.invalid")
            time.sleep(0.3)
        finally:
            srv.shutdown()
        ent = app.LOG.query(0, 900, "tls")
        self.assertTrue(any("FAILED" in e["text"] for e in ent),
                        "a client-side cert rejection was not logged")
        self.assertTrue(any("FAILED" in e["text"] and
                            "totally.unlisted-name-xyz.invalid" in e["text"] for e in ent),
                        "SNI was not captured on the FAILED handshake (the case that matters: "
                        "the device tried to reach a name we never saw elsewhere)")

    def test_tls_legacy_mode_still_serves_modern_client(self):
        cert, key = app.ensure_cert(os.path.join(TMP, "c.crt"),
                                    os.path.join(TMP, "c.key"), log=lambda m: None)
        srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="https",
                                webroot="", mode="page", page="L", cfg_ip=TEST_IP,
                                tls=(cert, key), legacy=True)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", port), 5) as raw:
                with ctx.wrap_socket(raw, server_hostname="legacy.test") as tls:
                    tls.sendall(b"GET /l HTTP/1.1\r\nHost: legacy.test\r\n"
                                b"Connection: close\r\n\r\n")
                    self.assertIn(b"200", recvn(tls, 4096).split(b"\r\n")[0])
        finally:
            srv.shutdown()

    # ---------------- 8080 console ----------------
    def test_console_logserver_compatible_and_api(self):
        srv = app.LogHttpServer(("127.0.0.1", 0), app.ConsoleHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            marker = "XBOX-LINE-" + str(time.time())
            st, body, _ = http_get(f"http://127.0.0.1:{port}/log?line={urllib.parse.quote(marker)}")
            self.assertEqual((st, body), (200, b"ok"))
            with open(app.LOG.path, encoding="utf-8") as f:
                self.assertIn(marker, f.read())          # raw append, logserver.py style
            st, body, _ = http_get(f"http://127.0.0.1:{port}/log.txt")
            self.assertEqual(st, 200)
            self.assertIn(marker.encode(), body)
            st, body, _ = http_get(f"http://127.0.0.1:{port}/api/entries?since=0&limit=5")
            j = json.loads(body)
            self.assertIn("entries", j)
            self.assertLessEqual(len(j["entries"]), 5)
            st, body, _ = http_get(f"http://127.0.0.1:{port}/api/stats")
            self.assertIn("counts", json.loads(body))
            st, body, _ = http_get(f"http://127.0.0.1:{port}/health")
            self.assertTrue(json.loads(body)["ok"])
            # hand-typed garbage in the query string must not close the socket
            for qs in ("since=abc&limit=xyz", "since=&limit=", "since=-5&limit=99999",
                       "since=99999999999999999999"):
                st, body, _ = http_get(f"http://127.0.0.1:{port}/api/entries?{qs}")
                self.assertEqual(st, 200, qs)
                self.assertIn("entries", json.loads(body), qs)
            st, body, _ = http_get(f"http://127.0.0.1:{port}/")
            self.assertEqual(st, 200)
            self.assertIn(b"<html", body.lower())
        finally:
            srv.shutdown()

    def test_directory_listing_works_at_any_depth(self):
        """Root AND subdirectories must be listed, with links that keep working."""
        srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="http",
                                webroot=self.webroot, mode="auto", page="P",
                                cfg_ip=TEST_IP)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            st, body, _ = http_raw(port, "/", host="127.0.0.1")
            self.assertEqual(st, 200)
            self.assertIn(b"harness.html", body)             # root lists its files
            # a subdirectory of the webroot, with a file in it
            st, body, _ = http_raw(port, "/subdir/", host="127.0.0.1")
            self.assertEqual(st, 200, "subdirectory was not listed")
            self.assertIn(b"inside.txt", body)
            self.assertIn(b"sub-sub/", body)                 # nested dir shown as a dir
            # the link it produced must actually resolve
            st, body, _ = http_raw(port, "/subdir/inside.txt", host="127.0.0.1")
            self.assertEqual(st, 200)
            self.assertEqual(body, b"hello-from-subdir\n")
            # deeper still, and back up one level
            st, body, _ = http_raw(port, "/subdir/sub-sub/", host="127.0.0.1")
            self.assertEqual(st, 200)
            self.assertIn(b"deep.txt", body)
            self.assertIn(b'href="/subdir/"', body)          # ../ goes to /subdir/
            # an index.html wins over listing
            st, body, _ = http_raw(port, "/hasindex/", host="127.0.0.1")
            self.assertEqual(st, 200)
            self.assertEqual(body, b"<h1>INDEX</h1>\n")
            # ".." resolves within the webroot: /subdir/sub-sub/../ -> /subdir/
            st, body, _ = http_raw(port, "/subdir/sub-sub/../", host="127.0.0.1")
            self.assertEqual(st, 200)
            self.assertIn(b"inside.txt", body)
            # and one that would escape the webroot is refused
            st, body, _ = http_raw(port, "/../", host="127.0.0.1")
            self.assertEqual(st, 403, "traversal out of the webroot must be refused")
            st, body, _ = http_raw(port, "/subdir/../../", host="127.0.0.1")
            self.assertEqual(st, 403, "traversal out of the webroot must be refused")
        finally:
            srv.shutdown()

    # ---------------- log destinations ----------------
    def test_log_split_receiver_file_holds_only_8080_lines(self):
        """xbox-log-received.log = only what the console posted to :8080, verbatim.
        log.txt = everything the interceptor observed.  One file must not leak
        into the other."""
        recv = os.path.join(TMP, "split", "xbox-log-received.log")
        inter = os.path.join(TMP, "split", "log.txt")
        saved = app.LOG
        app.LOG = app.Log(recv, inter)
        try:
            # interceptor traffic: DNS + HTTP + a sys line
            cfg = app.DnsConfig(TEST_IP)
            u, t, up, tp = start_dns(cfg)
            try:
                udp_query(up, "split-test.example")
            finally:
                u.stop(); t.shutdown()
            srv = app.CaptureServer(("127.0.0.1", 0), app.CaptureHandler, scheme="http",
                                    webroot=self.webroot, mode="auto", page="P",
                                    cfg_ip=TEST_IP)
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                http_raw(port, "/harness.html", host="split.example")
            finally:
                srv.shutdown()
            # 8080 traffic, both shapes the harness uses
            app.log_raw("console-line-A")
            app.log_raw("console-line-B", "xbox-post")
            import http.server as _hs
            csrv = app.LogHttpServer(("127.0.0.1", 0), app.ConsoleHandler)
            cport = csrv.server_address[1]
            threading.Thread(target=csrv.serve_forever, daemon=True).start()
            try:
                http_get(f"http://127.0.0.1:{cport}/log?line="
                         + urllib.parse.quote("console-line-C"))
                st, body, _ = http_get(f"http://127.0.0.1:{cport}/log.txt")
                self.assertIn(b"console-line-A", body)
                self.assertNotIn(b"[HTTP", body)          # receiver file only
                self.assertNotIn(b"split.example", body)
                st, body, _ = http_get(f"http://127.0.0.1:{cport}/intercept.txt")
                self.assertIn(b"q=split-test.example", body)
                self.assertIn(b"host=split.example", body)
                self.assertNotIn(b"console-line-A", body)
            finally:
                csrv.shutdown()
        finally:
            app.LOG = saved

        recv_text = open(recv, encoding="utf-8").read()
        inter_text = open(inter, encoding="utf-8").read()
        for line in ("console-line-A", "console-line-B", "console-line-C"):
            self.assertIn(line, recv_text, "8080 line missing from the receiver log")
        # nothing the interceptor saw may appear in the receiver log
        for token in ("[DNS", "[HTTP", "[SYS", "[TLS", "split-test.example", "split.example"):
            self.assertNotIn(token, recv_text,
                             f"receiver log must not contain interceptor output ({token})")
        # and the receiver's lines must not appear in the interceptor log
        self.assertNotIn("console-line-A", inter_text)
        self.assertNotIn("console-line-B", inter_text)
        for token in ("[DNS", "[HTTP"):
            self.assertIn(token, inter_text, "intercepted log is missing its own lines")
        # receiver lines are verbatim: no timestamp/kind prefix added
        for line in recv_text.splitlines():
            self.assertFalse(line.startswith("["), f"receiver line was decorated: {line!r}")

    def test_default_log_paths_are_the_two_expected_files(self):
        sib = app.Log(os.path.join(TMP, "sib", "xbox-log-received.log"))
        self.assertEqual(os.path.basename(sib.path), "xbox-log-received.log")
        self.assertEqual(os.path.basename(sib.intercept), "log.txt")
        self.assertEqual(os.path.dirname(sib.path), os.path.dirname(sib.intercept))

    # ---------------- DHCP packet building ----------------
    def test_dhcp_build_offers_us_as_dns_and_router(self):
        d = app.DhcpServer.__new__(app.DhcpServer)      # no socket needed
        d.ip, d.mask, d.lease = TEST_IP, "255.255.255.0", 3600
        d.leases = {}
        pkt = d._build(b"\x01\x02\x03\x04", bytes.fromhex("aabbccddeeff"), "192.0.2.210", 2)
        self.assertEqual(pkt[0], 2)                      # BOOTREPLY
        self.assertEqual(pkt[16:20], socket.inet_aton("192.0.2.210"))
        opts, i = {}, 240
        while i < len(pkt):
            if pkt[i] == 255:
                break
            opts[pkt[i]] = pkt[i + 2:i + 2 + pkt[i + 1]]
            i += 2 + pkt[i + 1]
        self.assertEqual(opts[53], b"\x02")              # DHCPOFFER
        self.assertEqual(opts[54], socket.inet_aton(TEST_IP))
        self.assertEqual(opts[6], socket.inet_aton(TEST_IP))    # DNS -> us
        self.assertEqual(opts[3], socket.inet_aton(TEST_IP))    # router -> us
        # parse side: a real client request (op=1), not our own reply
        client = bytearray(pkt)
        client[0] = 1
        parsed = d._parse(bytes(client))
        self.assertEqual(parsed["chaddr"], bytes.fromhex("aabbccddeeff"))
        self.assertEqual(parsed["opts"][53], b"\x02")
        self.assertIsNone(d._parse(pkt), "own BOOTREPLY should be ignored, not parsed")

    def test_dhcp_pool_allocation_is_unique(self):
        d = app.DhcpServer.__new__(app.DhcpServer)
        d.ip, d.lease, d.leases = TEST_IP, 3600, {}
        d.start_octet, d.end_octet = 200, 202
        got = {d._alloc("aa:bb:cc:00:00:0" + str(i)) for i in range(3)}
        self.assertEqual(len(got), 3)
        self.assertTrue(all(a.startswith("192.0.2.") for a in got))
        self.assertNotIn(TEST_IP, got)


if __name__ == "__main__":
    import urllib.parse  # noqa: F401  (used inside a test)
    unittest.main(verbosity=2)
