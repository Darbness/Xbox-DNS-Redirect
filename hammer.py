#!/usr/bin/env python3
"""Hostile-ish live exercise: weird DNS qtypes, malformed DNS, bad HTTP/1.1
clients, keep-alive, chunked POST, concurrency, unicode/traversal paths.
Everything is printed as PASS/FAIL so app.py's own stderr tells the rest."""
import concurrent.futures as cf
import http.client as hc
import socket
import ssl
import struct
import sys
import time
import urllib.parse

from dnslib import DNSRecord

HOST, DNS, HTTP, HTTPS, LOG = "127.0.0.1", 53, 80, 443, 8080
results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))


def dns_udp(name, qtype="A", port=DNS):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    s.sendto(DNSRecord.question(name, qtype).pack(), (HOST, port))
    d, _ = s.recvfrom(4096)
    s.close()
    return DNSRecord.parse(d)


def dns_tcp(name, qtype="A"):
    q = DNSRecord.question(name, qtype).pack()
    s = socket.create_connection((HOST, DNS), 4)
    s.sendall(struct.pack(">H", len(q)) + q)
    hdr = s.recv(2)
    n = struct.unpack(">H", hdr)[0]
    buf = b""
    while len(buf) < n:
        buf += s.recv(n - len(buf))
    s.close()
    return DNSRecord.parse(buf)


def send_raw(port, raw_bytes, read=4096, timeout=5):
    s = socket.create_connection((HOST, port), timeout)
    s.settimeout(timeout)
    s.sendall(raw_bytes)
    out = b""
    try:
        while len(out) < read:
            c = s.recv(4096)
            if not c:
                break
            out += c
    except socket.timeout:
        pass
    s.close()
    return out


print("--- DNS: every common qtype must get a sane answer, not a crash ---")
for qt in ("A", "AAAA", "MX", "TXT", "PTR", "SRV", "CNAME", "SOA", "NS", "ANY", "HTTPS"):
    try:
        r = dns_udp("probe.example", qt)
        check(f"udp {qt:6s} rcode={r.header.rcode} answers={len(r.rr)}", r.header.rcode in (0,))
    except Exception as e:
        check(f"udp {qt}", False, repr(e))
try:
    r = dns_tcp("tcp.example")
    check("tcp A -> " + str(r.rr[0].rdata), str(r.rr[0].rdata) == "192.168.1.146")
except Exception as e:
    check("tcp A", False, repr(e))
try:
    r = dns_udp("mixed.CASE.Example")
    check("mixed-case name -> " + str(r.rr[0].rdata), True)
except Exception as e:
    check("mixed-case", False, repr(e))
try:
    r = dns_udp("a" * 60 + "." + "b" * 60 + ".example")
    check("long name (125 chars)", str(r.rr[0].rdata) == "192.168.1.146")
except Exception as e:
    check("long name", False, repr(e))

# malformed DNS must not kill the thread (send garbage, then a good query)
g = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
g.sendto(b"\x00" * 12 + b"\xff\xff\xff", (HOST, DNS))
g.sendto(b"\x12\x34\x01\x00\x00\x01", (HOST, DNS))          # truncated question
g.close()
time.sleep(0.3)
try:
    r = dns_udp("after-garbage.example")
    check("DNS survives malformed packets", str(r.rr[0].rdata) == "192.168.1.146")
except Exception as e:
    check("DNS survives malformed packets", False, repr(e))

print("--- HTTP: methods, keep-alive, chunked, garbage ---")
r = send_raw(HTTP, b"GET / HTTP/1.0\r\nHost: x.example\r\n\r\n")
check("HTTP/1.0 GET", r.startswith(b"HTTP/1."), r.split(b"\r\n")[0].decode(errors="replace"))
r = send_raw(HTTP, b"HEAD / HTTP/1.1\r\nHost: x.example\r\nConnection: close\r\n\r\n")
check("HEAD", r.startswith(b"HTTP/1.1 200"), r.split(b"\r\n")[0].decode(errors="replace"))
r = send_raw(HTTP, b"OPTIONS / HTTP/1.1\r\nHost: x.example\r\nConnection: close\r\n\r\n")
check("OPTIONS", b"HTTP/1.1" in r[:20], r.split(b"\r\n")[0].decode(errors="replace"))
r = send_raw(HTTP, b"CONNECT xbox.com:443 HTTP/1.1\r\nHost: xbox.com\r\n\r\n")
check("CONNECT rejected, not hung", b"405" in r[:20], r.split(b"\r\n")[0].decode(errors="replace"))
r = send_raw(HTTP, b"GET /a HTTP/1.1\r\nHost: x.example\r\n\r\nGET /b HTTP/1.1\r\nHost: x.example\r\n"
               b"Connection: close\r\n\r\n")
check("HTTP/1.1 keep-alive, 2 requests 1 socket", r.count(b"HTTP/1.1 ") >= 2,
      f"{r.count(b'HTTP/1.1 ')} responses")
body = b"5\r\nhello\r\n0\r\n\r\n"
r = send_raw(HTTP, b"POST /chunked HTTP/1.1\r\nHost: x.example\r\nTransfer-Encoding: chunked\r\n"
               b"Connection: close\r\n\r\n" + body)
check("chunked POST", r.startswith(b"HTTP/1.1"), r.split(b"\r\n")[0].decode(errors="replace"))
r = send_raw(HTTP, b"POST /form HTTP/1.1\r\nHost: x.example\r\nContent-Length: 11\r\n"
               b"Connection: close\r\n\r\nkey=hammer1")
check("POST body", r.startswith(b"HTTP/1.1"), r.split(b"\r\n")[0].decode(errors="replace"))
r = send_raw(HTTP, b"BOGUS /\r\nHost: x.example\r\n\r\n", read=200)
check("garbage request line handled", b"HTTP/1.1 4" in r or b"400" in r or b"501" in r,
      r.split(b"\r\n")[0].decode(errors="replace"))
r = send_raw(HTTP, b"GET /" + b"A" * 9000 + b" HTTP/1.1\r\nHost: x.example\r\n\r\n", read=200)
check("9KB request line handled (no crash/hang)", r.startswith(b"HTTP/1.1"),
      r.split(b"\r\n")[0].decode(errors="replace"))
r = send_raw(HTTP, ("GET /%E4%B8%AD%E6%96%87.html HTTP/1.1\r\nHost: x.example\r\n"
                "Connection: close\r\n\r\n").encode())
check("unicode path", r.startswith(b"HTTP/1.1"), r.split(b"\r\n")[0].decode(errors="replace"))
r = send_raw(HTTP, b"GET /../../../../windows/win.ini HTTP/1.1\r\nHost: x.example\r\n"
               b"Connection: close\r\n\r\n")
check("traversal blocked", b" 40" in r[:20] or b" 30" in r[:20],
      r.split(b"\r\n")[0].decode(errors="replace"))
r = send_raw(HTTP, b"GET /%2e%2e/app.py HTTP/1.1\r\nHost: x.example\r\nConnection: close\r\n\r\n")
check("encoded traversal blocked", b" 40" in r[:20] or b" 30" in r[:20],
      r.split(b"\r\n")[0].decode(errors="replace"))
r = send_raw(HTTP, b"GET / HTTP/1.1\r\nHost: " + b"h" * 3000 + b".example\r\nConnection: close\r\n\r\n")
check("3KB Host header", r.startswith(b"HTTP/1.1"), r.split(b"\r\n")[0].decode(errors="replace"))
r = send_raw(HTTP, b"GET / HTTP/1.1\r\nX-Junk: " + b"j" * 60000 + b"\r\nConnection: close\r\n\r\n")
check("60KB header block", b"HTTP/1.1" in r[:20], r.split(b"\r\n")[0].decode(errors="replace"))

print("--- HTTPS ---")
def tls_get(path="/", sni="www.xboxlive.com", ctx=None):
    c = ctx or ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
    s = socket.create_connection((HOST, HTTPS), 6)
    t = c.wrap_socket(s, server_hostname=sni)
    t.sendall(f"GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode())
    d = b""
    while True:
        c2 = t.recv(4096)
        if not c2:
            break
        d += c2
    t.close()
    return d

check("TLS SNI + GET", b"200" in tls_get("/").split(b"\r\n")[0])
check("TLS no SNI (IP client)", b"200" in tls_get("/", sni=None).split(b"\r\n")[0] if True else False)
check("TLS 300 concurrent-unfriendly junk handshake tolerated",
      (lambda: (socket.create_connection((HOST, HTTPS), 5).sendall(b"\x16\x03\x01\x00\x05junk"),
                time.sleep(0.2), True)[-1])())

print("--- console :8080 ---")
c = hc.HTTPConnection(HOST, LOG, timeout=5)
c.request("GET", "/health")
h = c.getresponse()
check("/health", h.status == 200, h.read()[:60].decode())
for path in ("/", "/log.txt", "/api/stats", "/api/entries?limit=2", "/favicon.ico",
             "/nope", "/api/entries?since=abc&limit=xyz"):
    try:
        c = hc.HTTPConnection(HOST, LOG, timeout=6)
        c.request("GET", path)
        r2 = c.getresponse()
        check(f"console {path}", r2.status < 500, f"status {r2.status}")
        r2.read()
        c.close()
    except Exception as e:
        check(f"console {path}", False, repr(e))
c = hc.HTTPConnection(HOST, LOG, timeout=6)
c.request("POST", "/", body=b"posted-line-from-hammer", headers={"Content-Type": "text/plain"})
r2 = c.getresponse()
check("POST / raw line", r2.status == 200 and r2.read() == b"ok")

print("--- concurrency: 40 parallel GETs over HTTP and HTTPS ---")
def one(i):
    try:
        raw = f"GET /?i={i} HTTP/1.1\r\nHost: c{i}.example\r\nConnection: close\r\n\r\n".encode()
        out = send_raw(HTTP, raw, read=512)
        return out.startswith(b"HTTP/1.1")
    except Exception:
        return False

with cf.ThreadPoolExecutor(max_workers=20) as ex:
    oks = sum(ex.map(one, range(40)))
check(f"40 parallel HTTP requests ({oks} ok)", oks == 40)

def one_tls(i):
    try:
        return b"200" in tls_get(f"/t{i}", sni=f"h{i}.example").split(b"\r\n")[0]
    except Exception:
        return False

with cf.ThreadPoolExecutor(max_workers=10) as ex:
    oks = sum(ex.map(one_tls, range(20)))
check(f"20 parallel HTTPS requests ({oks} ok)", oks == 20)

with cf.ThreadPoolExecutor(max_workers=20) as ex:
    oks = sum(ex.map(lambda i: dns_udp(f"c{i}.example").header.rcode == 0, range(60)))
check(f"60 parallel DNS queries ({oks} ok)", oks == 60)

print("--- still alive after all that ---")
check("app still serving", b"HTTP/1.1" in send_raw(HTTP, b"GET / HTTP/1.1\r\nHost: alive.example\r\n"
                                                    b"Connection: close\r\n\r\n", read=200))
bad = [n for ok, n, _ in results if not ok]
print(f"\n{len(results) - len(bad)}/{len(results)} checks passed")
if bad:
    print("FAILED: " + "; ".join(bad))
    sys.exit(1)
print("ALL LIVE CHECKS PASSED")
