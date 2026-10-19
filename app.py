#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
all-in-one DNS hijack + capture + log console.

ONE process does all of this:

  DNS  (UDP+TCP :53)   answers every query so that everything resolves to --ip.
                       A   -> --ip (ttl 0)
                       AAAA-> NODATA (so clients fall back to A)
                       queries on --bypass / --forward-all are relayed to
                       --upstream and their real answers returned.
                       every query is logged.
  HTTP (:80)           catch-all: any Host, any path.  Serves files out of
                       --webroot when present, otherwise redirects to https.
  HTTPS(:443)          same handler over TLS with an auto-generated self-signed
                       cert (certs/server.crt|key.pem).  Logs SNI *and* TLS
                       handshake failures (a client that rejects the cert is
                       itself evidence).  No trusted CA needed for logging.
  LOG  (:8080)         logserver.py-compatible receiver (/log?line=... and
                       /log.txt) PLUS a live dashboard, /api/entries,
                       /api/stats.
  DHCP (:67)           optional (--dhcp): hands out --ip as DNS+router so every
                       device on the LAN resolves through us without touching
                       any client config.  Off by default, loud about it.

Logging destination defaults to ..\\xbox-log-received.log (the same file
logserver.py appends to) plus ..\\xbox-log-received.jsonl for the API/dashboard.

Usage on the PC (192.168.1.146):
    python app.py                          # dns 53 + http 80 + https 443 + log 8080
    python app.py --webroot ".."           # also serve the exploit harnesses
    python app.py --forward-all            # pure DNS relay + logging (recon)
    python app.py --bypass xboxlive.com --forward-all
    python app.py --dhcp                   # hijack the whole LAN via DHCP
    python app.py --dns-port 5353 --http-port 8081 --https-port 8443   # unprivileged test
    python app.py --selftest               # no ports bound; quick built-in checks

Ctrl+C stops everything.  Windows does NOT need admin to bind 53/80/443, but a
URL/port reservation held by another service (IIS, WinNAT, http.sys) will make
the bind fail -- the startup report tells you exactly which port and why.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import datetime as _dt
import hashlib
import http.server
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
import traceback
import urllib.parse

try:
    from dnslib import (A, AAAA, QTYPE, RR, SOA, DNSHeader, DNSLabel, DNSQuestion,
                        DNSRecord, RCODE)
except ImportError as _e:  # pragma: no cover
    sys.exit(f"dnslib import failed ({_e}); install it with:  python -m pip install dnslib")

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)
CERT_DIR = os.path.join(HERE, "certs")
DEFAULT_CERT = os.path.join(CERT_DIR, "server.crt")
DEFAULT_KEY = os.path.join(CERT_DIR, "server.key")
# Web content and logs live in their own folders beside this script:
#   lan_dns_web\webroot  -- served as the base web directory
#   lan_dns_web\logs     -- every log file lands here
DEFAULT_WEBROOT = os.path.join(HERE, "webroot")
DEFAULT_LOGDIR = os.path.join(HERE, "logs")
DEFAULT_LOGFILE = os.path.join(DEFAULT_LOGDIR, "xbox-log-received.log")

VERSION = "1.0"
MAX_BODY = 64 * 1024
BANNER = "all-in-one-dns-web-log"

SAN_NAMES = [
    "*.local", "localhost", "*.localhost", "*.test", "*.example.com", "*.invalid",
    "*.microsoft.com", "*.windows.com", "*.windowsupdate.com", "*.msn.com",
    "*.live.com", "*.xboxlive.com", "*.xbox.com", "*.s-microsoft.com", "*.bing.com",
    "*.office.com", "*.office365.com", "*.google.com", "*.googleapis.com",
    "*.gstatic.com", "*.youtube.com", "*.googlevideo.com", "*.cloudflare.com",
    "*.akamai.net", "*.akamaized.net", "*.akamaihd.net", "*.edgekey.net",
    "*.edgesuite.net", "*.amazonaws.com", "*.cloudfront.net", "*.facebook.com",
    "*.fbcdn.net", "*.instagram.com", "*.whatsapp.net", "*.apple.com", "*.icloud.com",
    "*.mzstatic.com", "*.netflix.com", "*.nflxvideo.net", "*.spotify.com",
    "*.twitch.tv", "*.ttvnw.net", "*.discord.com", "*.discordapp.com",
    "*.steampowered.com", "*.steamstatic.com", "*.roblox.com", "*.rbxcdn.com",
    "*.epicgames.com", "*.playstation.net", "*.nintendo.net", "*.adobe.com",
    "*.dropbox.com", "*.github.com", "*.githubusercontent.com", "*.mozilla.org",
    "*.firefox.com", "*.samsung.com", "*.hulu.com", "*.disneyplus.com",
    "*.bamgrid.com", "*.wikipedia.org", "*.reddit.com", "*.redd.it", "*.imgur.com",
    "*.speedtest.net", "*.ookla.com", "*",
]


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def now_iso() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def now_short() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


SO_EXCLUSIVEADDRUSE = getattr(socket, "SO_EXCLUSIVEADDRUSE", 0x4)


def tune_listen_sock(sock, exclusive: bool = True, udp: bool = False) -> None:
    """Windows: SO_REUSEADDR lets ANOTHER process bind the same port and steal
    the traffic (that is how mDNS quietly owns :5353).  We want the opposite:
    bind exclusively so either we get the traffic or the startup report fails
    loudly -- never a socket that looks bound but is not receiving."""
    if os.name == "nt":
        if exclusive:
            try:
                sock.setsockopt(socket.SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                pass
        if udp:
            disable_udp_conn_reset(sock)
        return
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if udp:
        disable_udp_conn_reset(sock)


SIO_UDP_CONNRESET = 0x9800000C


def disable_udp_conn_reset(sock) -> bool:
    """Windows-only: by default a UDP socket inherits the ICMP port-unreachable
    that follows a reply to a client which already closed its socket, and the
    NEXT recvfrom() on that socket fails with WSAECONNRESET (10054).  A DNS
    server whose clients come and go (every stub resolver does) then dies after
    the first unreachable reply -- silently, with a bound port.  SIO_UDP_CONNRESET
    = FALSE turns that behaviour off.  Verified by test_udp_survives_icmp_reset."""
    try:
        ws2_32 = ctypes.windll.ws2_32
        inbuf = ctypes.c_uint32(0)          # FALSE
        ret = ctypes.c_uint32(0)
        rc = ws2_32.WSAIoctl(ctypes.c_void_p(sock.fileno()),
                             ctypes.c_uint32(SIO_UDP_CONNRESET),
                             ctypes.byref(inbuf), ctypes.c_uint32(4),
                             None, ctypes.c_uint32(0),
                             ctypes.byref(ret), None, None)
        return rc == 0
    except Exception:
        return False


class ExclusiveBind:
    """socketserver mixin: exclusive listener on Windows, SO_REUSEADDR elsewhere."""
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt":
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                pass
        super().server_bind()

    def handle_error(self, request, client_address):
        """A device that walks away mid-request is normal here (probes, consoles
        giving up on our cert).  Log one line, don't dump a traceback per event."""
        exc = sys.exc_info()[1]
        where = f"{client_address[0]}:{client_address[1]}"
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError,
                            BrokenPipeError, TimeoutError, ssl.SSLError)):
            log_add("sys", f"{where} dropped mid-request ({type(exc).__name__}: {exc})")
            return
        log_add("sys", f"server error for {where}: {type(exc).__name__}: {exc}")
        traceback.print_exc()


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def local_ip() -> str:
    """Best-effort LAN address of this machine (no traffic is actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def human(n: int) -> str:
    for unit in ("B", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return f"{n}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n}G"


def esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("\r", "\\r").replace("\n", "\\n"))


# --------------------------------------------------------------------------
# logging -- two separate destinations, deliberately:
#
#   xbox-log-received.log  ONLY what arrives on port 8080 (/log?line=, POST /),
#                          appended byte-for-byte exactly like logserver.py, so
#                          the file stays a straight transcript of what the
#                          console sent and nothing else.
#   log.txt                everything this server observes itself: DNS, HTTP,
#                          HTTPS, TLS handshakes, DHCP, sys messages -- prefixed
#                          with a timestamp and the kind.
#
# Both also land in the in-memory ring buffer (dashboard / /api/entries), and
# lone interceptor events are mirrored to log.txt.jsonl.
# --------------------------------------------------------------------------
class Log:
    def __init__(self, path: str, intercept: str | None = None, keep: int = 4000):
        self.path = path                                     # 8080 receiver log
        self.intercept = intercept or os.path.join(
            os.path.dirname(os.path.abspath(path)) or ".", "log.txt")
        self.jsonl = self.intercept + ".jsonl"
        self.lock = threading.RLock()
        self.entries = []          # list of dicts (live view, both destinations)
        self.keep = keep
        self.next_id = 0
        self.counts: dict[str, int] = {}
        self.hosts: dict[str, int] = {}
        self.paths: dict[str, int] = {}
        self.clients: dict[str, int] = {}
        for p in (self.path, self.intercept, self.jsonl):
            d = os.path.dirname(os.path.abspath(p))
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)

    def _append(self, path: str, line: str) -> None:
        try:
            with open(path, "a", encoding="utf-8", errors="replace") as f:
                f.write(line)
        except OSError as e:
            print(f"[log] write failed to {path}: {e}")

    # -- 8080 receiver: byte-for-byte what logserver.py writes ---------------
    def raw(self, line: str, src: str = "xbox") -> None:
        self.add("xlog", line, src=src)          # add() routes xlog to self.path

    def add(self, kind: str, text: str, *, src: str | None = None, **meta) -> dict:
        with self.lock:
            self.next_id += 1
            e = {"id": self.next_id, "ts": now_iso(), "kind": kind, "text": text,
                 "src": src, "meta": meta}
            self.entries.append(e)
            if len(self.entries) > self.keep:
                del self.entries[:len(self.entries) - self.keep]
            self.counts[kind] = self.counts.get(kind, 0) + 1
            if src:
                self.clients[src] = self.clients.get(src, 0) + 1
            host = meta.get("host")
            if host:
                self.hosts[host] = self.hosts.get(host, 0) + 1
            path = meta.get("path")
            if path:
                self.paths[path] = self.paths.get(path, 0) + 1
            if kind == "xlog":
                # the console's own line, verbatim, into its own file
                self._append(self.path, text + "\n")
            else:
                self._append(self.intercept,
                             f"[{e['ts']}] [{kind.upper():5s}] {text}\n")
            try:
                with open(self.jsonl, "a", encoding="utf-8", errors="replace") as f:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
            except OSError:
                pass
        return e

    def query(self, since: int = 0, limit: int = 500, kind: str = "",
              needle: str = "") -> list[dict]:
        with self.lock:
            out = []
            for e in reversed(self.entries):
                if e["id"] <= since:
                    continue
                if kind and kind != "all" and e["kind"] != kind:
                    continue
                if needle and needle.lower() not in json.dumps(e).lower():
                    continue
                out.append(e)
                if len(out) >= limit:
                    break
            out.reverse()
            return out

    @staticmethod
    def _read(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def text(self) -> str:
        """The 8080 receiver log (what /log.txt serves, logserver.py style)."""
        return self._read(self.path)

    def intercept_text(self) -> str:
        """Everything this server observed: DNS/HTTP/HTTPS/TLS/DHCP/sys."""
        return self._read(self.intercept)

    def stats(self) -> dict:
        with self.lock:
            def top(d, n=15):
                return sorted(d.items(), key=lambda kv: -kv[1])[:n]
            return {"total": sum(self.counts.values()), "counts": dict(self.counts),
                    "clients": top(self.clients), "hosts": top(self.hosts),
                    "paths": top(self.paths), "last_id": self.next_id,
                    "receiver_log": self.path, "intercept_log": self.intercept,
                    "jsonl": self.jsonl}


LOG: Log | None = None


def log_raw(line: str, src: str = "xbox") -> None:
    if LOG:
        LOG.raw(line, src)


def log_add(kind: str, text: str, **kw) -> None:
    if LOG:
        LOG.add(kind, text, **kw)


# --------------------------------------------------------------------------
# self-signed cert generation (pure stdlib: RSA + minimal DER/X.509)
# --------------------------------------------------------------------------
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(payload)) + payload


def _int(v: int) -> bytes:
    if v == 0:
        return b"\x02\x01\x00"
    b = v.to_bytes((v.bit_length() + 8) // 8, "big")
    return _tlv(0x02, b)


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _set(*items: bytes) -> bytes:
    return _tlv(0x31, b"".join(items))


def _octet(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _bitstr(data: bytes, unused: int = 0) -> bytes:
    return _tlv(0x03, bytes([unused]) + data)


def _utf8(s: str) -> bytes:
    return _tlv(0x0c, s.encode("utf-8"))


def _utc(dt: _dt.datetime) -> bytes:
    return _tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode())


def _ctx(n: int, payload: bytes, constructed: bool = True) -> bytes:
    return _tlv((0xA0 if constructed else 0x80) + n, payload)


def _oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            out.append(p)
        else:
            chunk = []
            while p:
                chunk.append(p & 0x7F)
                p >>= 7
            for i, c in enumerate(reversed(chunk)):
                out.append(c | (0x80 if i < len(chunk) - 1 else 0))
    return _tlv(0x06, bytes(out))


OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_RSA = "1.2.840.113549.1.1.1"
OID_CN, OID_O, OID_C = "2.5.4.3", "2.5.4.10", "2.5.4.6"
OID_SAN, OID_BC, OID_KU, OID_EKU = "2.5.29.17", "2.5.29.19", "2.5.29.15", "2.5.29.37"
OID_SKI, OID_AKI = "2.5.29.14", "2.5.29.35"
OID_SERVER_AUTH, OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"

_ALG_SHA256_RSA = _seq(_oid(OID_SHA256_RSA), b"\x05\x00")

_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
                 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
                 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
                 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
                 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
                 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433,
                 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
                 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
                 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677,
                 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769,
                 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
                 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
                 967, 971, 977, 983, 991, 997]


def _is_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if any(cand % p == 0 for p in _SMALL_PRIMES):
            continue
        if _is_prime(cand):
            return cand


def gen_rsa(bits: int = 2048, e: int = 65537) -> dict:
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits - bits // 2)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
        except ValueError:
            continue
        dp, dq = d % (p - 1), d % (q - 1)
        try:
            qinv = pow(q, -1, p)
        except ValueError:
            continue
        return {"n": n, "e": e, "d": d, "p": p, "q": q, "dp": dp, "dq": dq,
                "qinv": qinv, "bits": bits}


_DIGESTINFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def _pkcs1_sign(msg: bytes, key: dict) -> bytes:
    t = _DIGESTINFO_SHA256 + hashlib.sha256(msg).digest()
    k = (key["n"].bit_length() + 7) // 8
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), key["d"], key["n"]).to_bytes(k, "big")


def _name(cn: str, org: str = BANNER, country: str = "AU") -> bytes:
    return _seq(_set(_seq(_oid(OID_C), _utf8(country))),
                _set(_seq(_oid(OID_O), _utf8(org))),
                _set(_seq(_oid(OID_CN), _utf8(cn))))


def _san_ext(names: list[str], ips: list[str]) -> bytes:
    items = [_ctx(2, n.encode(), constructed=False) for n in names]
    for ip in ips:
        try:
            items.append(_ctx(7, ipaddress.ip_address(ip).packed, constructed=False))
        except ValueError:
            pass
    return _seq(_oid(OID_SAN), _octet(_seq(*items)))


def _ext(oid: str, value: bytes, critical: bool = False) -> bytes:
    parts = [_oid(oid)]
    if critical:
        parts.append(b"\x01\x01\xff")
    parts.append(_octet(value))
    return _seq(*parts)


def make_self_signed(cn: str, san_names: list[str], san_ips: list[str],
                     days: int = 825, bits: int = 2048,
                     key: dict | None = None) -> tuple[str, str]:
    """Return (cert_pem, key_pem) for a fresh self-signed RSA cert."""
    key = key or gen_rsa(bits)
    spki = _seq(_seq(_oid(OID_RSA), b"\x05\x00"),
                _bitstr(_seq(_int(key["n"]), _int(key["e"]))))
    pub_der = _seq(_int(key["n"]), _int(key["e"]))
    ski = hashlib.sha1(pub_der).digest()
    utcnow = _dt.datetime.now(_dt.timezone.utc)
    not_before = utcnow - _dt.timedelta(hours=1)
    not_after = utcnow + _dt.timedelta(days=days)
    serial = secrets.randbits(63) | 1
    tbs = _seq(
        _ctx(0, _int(2)),                              # v3
        _int(serial),
        _ALG_SHA256_RSA,
        _name(cn),
        _seq(_utc(not_before), _utc(not_after)),
        _name(cn),
        spki,
        _ctx(3, _seq(                                     # [3] EXPLICIT extensions
            _ext(OID_BC, _seq(b"\x01\x01\xff"), critical=True),   # CA:TRUE
            _ext(OID_KU, _bitstr(b"\xa4", 2), critical=True),     # digSig,keyEnc,certSign
            _ext(OID_EKU, _seq(_oid(OID_SERVER_AUTH), _oid(OID_CLIENT_AUTH))),
            _san_ext(san_names, san_ips),
            _ext(OID_SKI, _octet(ski)),
            _ext(OID_AKI, _seq(_ctx(0, ski, constructed=False))),
        )),
    )
    cert = _seq(tbs, _ALG_SHA256_RSA, _bitstr(_pkcs1_sign(tbs, key)))
    key_der = _seq(_int(0), _int(key["n"]), _int(key["e"]), _int(key["d"]),
                   _int(key["p"]), _int(key["q"]), _int(key["dp"]),
                   _int(key["dq"]), _int(key["qinv"]))
    return _pem("CERTIFICATE", cert), _pem("RSA PRIVATE KEY", key_der)


def _pem(label: str, der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


def ensure_cert(cert_path: str = DEFAULT_CERT, key_path: str = DEFAULT_KEY,
                names: list[str] | None = None, ips: list[str] | None = None,
                days: int = 825, force: bool = False, log=print) -> tuple[str, str]:
    """Generate + cache a self-signed cert covering every redirect name."""
    names = list(dict.fromkeys(names or SAN_NAMES))
    ips = list(dict.fromkeys(ips or ["127.0.0.1", "::1", local_ip()]))
    if not force and os.path.isfile(cert_path) and os.path.isfile(key_path):
        log(f"using existing cert {cert_path}")
        return cert_path, key_path
    os.makedirs(os.path.dirname(cert_path) or ".", exist_ok=True)
    t0 = time.time()
    cert_pem, key_pem = make_self_signed(BANNER, names, ips, days=days)
    with open(cert_path, "w", encoding="ascii") as f:
        f.write(cert_pem)
    with open(key_path, "w", encoding="ascii") as f:
        f.write(key_pem)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    log(f"generated self-signed cert ({len(names)} SAN names, {days}d, "
        f"{time.time() - t0:.1f}s) -> {cert_path}")
    return cert_path, key_path


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------
def _soa(qname: DNSLabel) -> RR:
    return RR(qname, QTYPE.SOA, ttl=0,
              rdata=SOA(mname="ns." + str(qname).strip(".") or BANNER,
                        rname="hostmaster." + str(qname).strip("."),
                        times=(0, 0, 0, 0, 0)))


def dns_reply(question, redirect_ip: str, logger=None, ttl: int = 0,
              aaaa_mode: str = "nodata") -> DNSRecord:
    """Build the synthetic reply for any query.

    A     -> redirect_ip
    AAAA  -> NODATA (client retries over IPv4)
    other -> NODATA (+SOA so negative answers are well formed)

    Accepts a DNSRecord (full query) or a DNSQuestion, which is what
    test_app.py passes: dns_reply(DNSRecord.question('x'), ip, None).
    """
    if isinstance(question, DNSRecord):
        q = question.q
        reply = DNSRecord(DNSHeader(id=question.header.id, qr=1, aa=1, ra=1), q=q)
    else:
        q = question
        reply = DNSRecord(DNSHeader(id=0, qr=1, aa=1, ra=1), q=q)
    qtype = QTYPE.get(q.qtype, str(q.qtype))
    if qtype == "A":
        reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(redirect_ip), ttl=ttl))
    elif qtype == "AAAA":
        if aaaa_mode == "redirect":
            reply.add_answer(RR(q.qname, QTYPE.AAAA,
                                rdata=AAAA("::ffff:" + redirect_ip), ttl=ttl))
        else:
            reply.add_auth(_soa(q.qname))
    else:
        reply.add_auth(_soa(q.qname))
    if logger:
        logger(f"dns_reply q={q.qname} {qtype} -> {redirect_ip if qtype == 'A' else 'nodata'}")
    return reply


class DnsConfig:
    def __init__(self, ip: str, ttl: int = 0, aaaa_mode: str = "nodata",
                 upstreams: list[str] | None = None, bypass: list[str] | None = None,
                 forward_all: bool = False, fail_closed: bool = True):
        self.ip = ip
        self.ttl = ttl
        self.aaaa_mode = aaaa_mode
        self.upstreams = upstreams or []
        self.bypass = [b.lower().strip(".") for b in (bypass or [])]
        self.forward_all = forward_all
        self.fail_closed = fail_closed

    def should_forward(self, qname: str) -> bool:
        if not self.upstreams:
            return False
        name = qname.lower().strip(".")
        for b in self.bypass:
            if name == b or name.endswith("." + b):
                return True
        return self.forward_all


def _forward(query: DNSRecord | bytes, upstreams: list[str], timeout: float = 2.0
             ) -> tuple[bytes | None, str | None]:
    """Relay a raw query to the first upstream that answers."""
    raw = query.pack() if isinstance(query, DNSRecord) else query
    for up in upstreams:
        host, _, port = up.partition(":")
        port = int(port or 53)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(raw, (host, port))
            data, _ = s.recvfrom(4096)
            if data[:2] == raw[:2]:
                return data, up
        except OSError:
            continue
        finally:
            s.close()
    return None, None


def handle_dns_query(raw: bytes, addr, cfg: DnsConfig) -> tuple[bytes | None, str, dict]:
    """Answer one raw DNS message.  Returns (bytes|None, action, logmeta)."""
    try:
        return _handle_dns_query(raw, addr, cfg)
    except Exception as e:                       # never let one packet kill the server
        meta = {"src": addr[0], "port": addr[1], "host": "-",
                "error": f"{type(e).__name__}: {e}"}
        log_add("sys", f"DNS internal error on packet from {addr[0]} "
                       f"({len(raw)}B): {type(e).__name__}: {e}")
        return None, f"internal-error({type(e).__name__})", meta


def _handle_dns_query(raw: bytes, addr, cfg: DnsConfig) -> tuple[bytes | None, str, dict]:
    meta = {"src": addr[0], "port": addr[1]}
    try:
        rec = DNSRecord.parse(raw)
    except Exception as e:
        meta["host"] = "-"
        return None, f"parse-error({e})", meta
    q = rec.q
    qname = str(q.qname).rstrip(".")
    qtype = QTYPE.get(q.qtype, str(q.qtype))
    meta["host"] = qname
    meta["qtype"] = qtype

    if cfg.should_forward(qname):
        data, up = _forward(rec, cfg.upstreams)
        if data:
            try:
                f = DNSRecord.parse(data)
                answers = ",".join(str(rr.rdata) for rr in f.rr)
                meta["answer"] = answers[:200]
            except Exception:
                pass
            return data, f"forward->{up}", meta
        meta["answer"] = "upstream-timeout"
        if not cfg.fail_closed:
            return dns_reply(rec, cfg.ip, ttl=cfg.ttl, aaaa_mode=cfg.aaaa_mode).pack(), \
                "upstream-down(fail-open)", meta
        r = DNSRecord(DNSHeader(id=rec.header.id, qr=1, aa=0, ra=1, rcode=RCODE.SERVFAIL), q=q)
        return r.pack(), "upstream-down(servfail)", meta

    reply = dns_reply(rec, cfg.ip, ttl=cfg.ttl, aaaa_mode=cfg.aaaa_mode)
    if qtype == "A":
        meta["answer"] = cfg.ip
        action = "redirect"
    else:
        meta["answer"] = "nodata"
        action = "nodata"
    return reply.pack(), action, meta


class DnsUdpServer(threading.Thread):
    def __init__(self, bind: str, port: int, cfg: DnsConfig):
        super().__init__(daemon=True, name=f"dns-udp:{port}")
        self.bind, self.port, self.cfg = bind, port, cfg
        self.stop_flag = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tune_listen_sock(self.sock, udp=True)
        self.sock.bind((bind, port))
        self.errors = 0

    def run(self):
        while not self.stop_flag.is_set():
            try:
                raw, addr = self.sock.recvfrom(4096)
            except OSError as e:
                if self.stop_flag.is_set():
                    break
                err = getattr(e, "winerror", None) or e.errno
                if err in (10038, 9, 10022):        # WSAENOTSOCK/EBADF/EINVAL: socket gone
                    log_add("sys", f"DNS/udp socket closed ({e}); listener stopped")
                    break
                # transient (WSAECONNRESET 10054 after an ICMP port-unreachable
                # from a client that already left, EINTR, ...): keep serving
                self.errors += 1
                if self.errors in (1, 10, 100) or self.errors % 1000 == 0:
                    log_add("sys", f"DNS/udp transient recv error #{self.errors} "
                                   f"[{err}] {e} -- still listening")
                continue
            out, action, meta = handle_dns_query(raw, addr, self.cfg)
            if out:
                try:
                    self.sock.sendto(out, addr)
                except OSError:
                    pass
            log_add("dns", f"{meta.get('src')} q={meta.get('host')} {meta.get('qtype')} "
                           f"-> {meta.get('answer','-')} [{action}]",
                    **{k: v for k, v in meta.items()})

    def stop(self):
        self.stop_flag.set()
        try:
            self.sock.close()
        except OSError:
            pass


class DnsTcpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        cfg: DnsConfig = getattr(self.server, "dns_cfg", None)
        if cfg is None:                      # never crash the TCP listener
            return
        try:
            head = self._readn(2)
            if len(head) < 2:
                return
            n = struct.unpack(">H", head)[0]
            raw = self._readn(n)
            if len(raw) < n:
                return
            out, action, meta = handle_dns_query(raw, self.client_address, cfg)
            if out:
                self.request.sendall(struct.pack(">H", len(out)) + out)
            log_add("dns", f"{meta.get('src')} q={meta.get('host')} {meta.get('qtype')} "
                           f"-> {meta.get('answer','-')} [{action}/tcp]", **meta)
        except OSError:
            pass

    def _readn(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf


class DnsTcpServer(ExclusiveBind, socketserver.ThreadingTCPServer):
    daemon_threads = True


# --------------------------------------------------------------------------
# HTTP / HTTPS capture
# --------------------------------------------------------------------------
COMMON_UA_KEYS = ("User-Agent", "Host", "Referer", "Cookie", "Content-Type",
                  "Accept", "SOAPAction", "X-Requested-With", "Authorization")

# No fabricated responses live in this file.  Every byte served comes from
# --webroot; if a path has no file there, the request is redirected to our own
# address (which then serves --webroot again).  If you want a device's
# connectivity probe answered (e.g. /ncsi.txt, /xboxncsi.txt), put that file in
# the webroot -- the content is yours, not invented by the server.


class CaptureHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AllInOne/" + VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # silence stdlib access log
        pass

    # every verb lands in the same place
    def do_GET(self):
        self._capture()

    do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = do_CONNECT = do_GET

    def _read_body(self) -> bytes:
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            out, total = b"", 0
            try:
                while True:
                    line = self.rfile.readline(64).strip()
                    size = int(line.split(b";")[0] or b"0", 16)
                    if size == 0:
                        self.rfile.readline(64)
                        break
                    chunk = self.rfile.read(size)
                    total += len(chunk)
                    if total <= MAX_BODY:
                        out += chunk
                    self.rfile.read(2)
                    if total > 4 * MAX_BODY:
                        break
            except (OSError, ValueError):
                pass
            return out
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return b""
        return self.rfile.read(min(n, MAX_BODY))

    def _headers_log(self) -> str:
        parts = []
        for k in COMMON_UA_KEYS:
            v = self.headers.get(k)
            if v:
                parts.append(f"{k}={v[:160]}")
        return " ".join(parts)

    def _client(self) -> str:
        return f"{self.client_address[0]}:{self.client_address[1]}"

    def _is_us(self, host: str) -> bool:
        """True when the request already came to our own address (post-redirect)."""
        me = {getattr(self.server, "cfg_ip", ""), "127.0.0.1", "localhost", "::1"}
        return (host or "").lower() in me

    def _sni(self) -> str | None:
        name = getattr(self.connection, "sni_hostname", None)
        if name:
            return name
        with _SNI_LOCK:
            return _SNI.get(id(self.connection))

    def _capture(self):
        scheme = getattr(self.server, "scheme", "http")
        body = self._read_body()
        host = (self.headers.get("Host") or "").split(":")[0]
        sni = self._sni()
        status, note = self._respond(body)
        kind = "https" if scheme == "https" else "http"
        line = (f"{self._client()} {self.command} {self.path} {self.request_version} "
                f"host={host or '-'} sni={sni or '-'} {self._headers_log()} "
                f"body={len(body)}B -> {status} {note}")
        LOG and LOG.add(kind, line, src=self.client_address[0], host=host,
                        path=self.path, method=self.command, status=status,
                        sni=sni, bytes=len(body), body=body[:400].decode("utf-8", "replace")
                        if body else "")
        if sni and host and sni != host:
            log_add("tls", f"{self._client()} SNI {sni} != Host {host} (probe/{scheme})",
                    src=self.client_address[0], host=sni)

    def _respond(self, body: bytes) -> tuple[int, str]:
        srv = self.server
        mode = srv.mode
        path = urllib.parse.urlparse(self.path).path
        host = (self.headers.get("Host") or srv.cfg_ip or "localhost").split(":")[0]

        if self.command == "CONNECT":
            self._send(405, b"CONNECT not supported", "text/plain")
            return 405, "connect-rejected"

        if mode in ("auto", "serve"):
            hit = self._static(path)
            if hit is not None:
                return hit
            if mode == "serve":
                self._send(404, b"not found", "text/plain")
                return 404, "no-file"

        # --- our own address: never bounce the client again (loop guard) ------
        # The redirect points at us, so the follow-up arrives with Host = our IP.
        # Redirecting that one too would loop forever; answer it locally instead.
        # What it gets is the landing page -- or the webroot file, had the lookup
        # above found one, in which case we never redirected in the first place.
        if self._is_us(host):
            self._send(200, srv.page, "text/html; charset=utf-8")
            return 200, "page(self)"

        if mode == "redirect" or (mode == "auto" and srv.scheme == "http"):
            # Target is OUR OWN address, same scheme, never the requested host and
            # never upgraded to https:
            #  * not <requested host> -- a cached answer, a DoH lookup or a
            #    hardcoded IP would send the device straight out to the real server;
            #  * not https -- a plain-HTTP fetch redirected to our self-signed TLS
            #    port dies at the handshake, so the device never gets content it
            #    would have accepted over http.
            port = self.server.server_address[1]
            try:
                target = srv.redirect_template.format(
                    host=host, path=self.path, ip=srv.cfg_ip, port=port)
            except (KeyError, IndexError, ValueError, AttributeError):
                target = f"{srv.scheme}://{srv.cfg_ip}{self.path}"
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return 302, f"redirect->{target}"

        if mode == "empty":
            self._send(204, b"", "text/plain")
            return 204, "empty"

        if mode == "page":
            page = srv.page
            self._send(200, page, "text/html; charset=utf-8")
            return 200, "page"

        # auto, https, nothing matched -> default landing page
        self._send(200, srv.page, "text/html; charset=utf-8")
        return 200, "page"

    def _send(self, code: int, body: bytes, ctype: str):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD" and body:
            try:
                self.wfile.write(body)
            except OSError:
                pass

    def _static(self, path: str):
        root = self.server.webroot
        if not root or not os.path.isdir(root):
            return None
        root = os.path.abspath(root)
        rel = urllib.parse.unquote(path).lstrip("/")
        full = os.path.normpath(os.path.join(root, rel))
        # containment: "/webroot" must not match "/webrootfoo"
        if full != root and not full.startswith(root + os.sep):
            self._send(403, b"forbidden", "text/plain")
            return 403, "traversal-blocked"
        if os.path.isfile(full):
            try:
                with open(full, "rb") as f:
                    data = f.read()
            except OSError as e:
                self._send(500, str(e).encode(), "text/plain")
                return 500, "read-error"
            ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
            self._send(200, data, ctype)
            return 200, f"file:{rel} ({human(len(data))})"
        if os.path.isdir(full):
            idx = os.path.join(full, "index.html")
            if os.path.isfile(idx):
                try:
                    with open(idx, "rb") as f:
                        data = f.read()
                except OSError as e:
                    self._send(500, str(e).encode(), "text/plain")
                    return 500, "read-error"
                self._send(200, data, "text/html; charset=utf-8")
                return 200, f"index:{rel or '.'} ({human(len(data))})"
            # a directory with no index.html: list it (root AND subdirectories)
            self._send(200, self._listing(full, rel), "text/html; charset=utf-8")
            return 200, f"dir-listing:{rel or '.'}"
        return None

    def _listing(self, full: str, rel: str) -> str:
        """HTML index of a directory.  `rel` is the request path relative to the
        webroot, so links are absolute and work at any depth."""
        rows = []
        try:
            names = sorted(os.listdir(full))
        except OSError as e:
            names = []
            rows.append(f'<li class="dim">cannot read directory: {esc(str(e))}</li>')
        here = rel.strip("/")
        prefix = "/" + here + "/" if here else "/"
        if here:                                     # a way back up
            up = "/" + "/".join(here.split("/")[:-1])
            up = (up.rstrip("/") or "") + "/"
            rows.append(f'<li><a href="{esc(up)}">../</a></li>')
        for name in names:
            if name.startswith(".") or name in ("certs", "__pycache__"):
                continue
            p = os.path.join(full, name)
            href = prefix + urllib.parse.quote(name)
            try:
                is_dir = os.path.isdir(p)
            except OSError:
                is_dir = False
            if is_dir:
                rows.append(f'<li><a href="{esc(href)}/">{esc(name)}/</a></li>')
            else:
                try:
                    n = os.path.getsize(p)
                except OSError:
                    n = 0
                rows.append(f'<li><a href="{esc(href)}">{esc(name)}</a> '
                            f'<span class="dim">{human(n)}</span></li>')
        title = esc(rel.strip("/") or "webroot")
        return ("<!doctype html><meta charset=utf-8><title>%s</title>"
                "<style>body{background:#111;color:#ddd;font:14px/1.5 ui-monospace,Consolas,monospace;"
                "padding:24px}a{color:#7cc7ff;text-decoration:none}a:hover{text-decoration:underline}"
                ".dim{color:#666}</style><h2>%s</h2><p class=dim>%s &nbsp; "
                "<a href=\"/\">[root]</a></p><ul>%s</ul>"
                % (BANNER, BANNER, title, "".join(rows)))


class CaptureServer(ExclusiveBind, http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, scheme="http", webroot="", mode="auto",
                 page="", redirect_template="", cfg_ip="", tls=None, legacy=False):
        self.scheme = scheme
        self.webroot = webroot
        self.mode = mode
        self.page = page
        self.cfg_ip = cfg_ip
        self.tls = tls
        self.legacy = legacy
        super().__init__(addr, handler)          # binds, so the port is known now
        # default: back to ourselves, SAME scheme ({path} keeps the query).
        # The port is included unless we are on 80, so an alt-port run redirects
        # somewhere that actually exists.
        bound = self.server_address[1]
        self.redirect_template = redirect_template or (
            "http://" + (cfg_ip or "{host}") + ("" if bound == 80 else ":{port}") + "{path}")

    def get_request(self):
        sock, addr = self.socket.accept()
        if not self.tls:
            return sock, addr
        try:
            ctx = _tls_context(self.tls, self.legacy)
            _SNI_TLS.pending = None
            tls = ctx.wrap_socket(sock, server_side=True)
            name = getattr(tls, "sni_hostname", None) or _sni_take()
            _SNI_FLUSH()
            log_add("tls", f"{addr[0]}:{addr[1]} TLS handshake ok "
                           f"{tls.version()} {tls.cipher()[0]} sni={name or '-'}"
                           + (f" [cert: {_SNI.get(id(tls))}]" if _SNI.get(id(tls)) else ""),
                    src=addr[0], host=name or "-", version=str(tls.version()))
            with _SNI_LOCK:
                _SNI_LAST[id(tls)] = _SNI.get(id(tls))
            return tls, addr
        except ssl.SSLError as e:
            sni = _sni_take() or _SNI_PEEK(id(sock))
            reason = f"{e.__class__.__name__}: {e}"
            log_add("tls", f"{addr[0]}:{addr[1]} TLS handshake FAILED sni={sni or '-'} "
                           f"({reason})  <- client rejected us or offered an "
                           f"unsupported version/cipher", src=addr[0], host=sni or "-",
                    error=reason)
            try:
                _SNI_POP(id(sock))
            except Exception:
                pass
            try:
                sock.close()
            except OSError:
                pass
            raise OSError("tls handshake failed") from None


_SNI: dict[int, str] = {}
_SNI_LAST: dict[int, str] = {}
_SNI_LOCK = threading.RLock()
# the ClientHello (and therefore the SNI) is processed on the same thread that
# called get_request, so this survives even when the client then aborts on our
# cert and wrap_socket throws -- that is the case we most want to log.
_SNI_TLS = threading.local()


def _sni_take() -> str | None:
    name = getattr(_SNI_TLS, "pending", None)
    _SNI_TLS.pending = None
    return name


def _SNI_PEEK(key: int) -> str | None:
    with _SNI_LOCK:
        return _SNI.get(key)


def _SNI_POP(key: int) -> None:
    with _SNI_LOCK:
        _SNI.pop(key, None)


def _SNI_FLUSH():
    with _SNI_LOCK:
        if len(_SNI) > 4096:
            _SNI.clear()


def _sni_callback(sslsock, server_name, ctx):
    if server_name:
        _SNI_TLS.pending = server_name
        with _SNI_LOCK:
            _SNI[id(sslsock)] = server_name
        try:
            sslsock.sni_hostname = server_name
        except Exception:
            pass


_TLS_CTX: dict[tuple, ssl.SSLContext] = {}
_TLS_LOCK = threading.Lock()


def _tls_context(paths: tuple[str, str], legacy: bool = False) -> ssl.SSLContext:
    with _TLS_LOCK:
        if paths in _TLS_CTX:
            return _TLS_CTX[paths]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(paths[0], paths[1])
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.sni_callback = _sni_callback
        if legacy:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            try:
                ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
            except AttributeError:
                pass
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        _TLS_CTX[paths] = ctx
        return ctx


DEFAULT_PAGE = """<!doctype html><meta charset=utf-8><title>%(banner)s</title>
<style>body{background:#111;color:#ddd;font:14px/1.6 ui-monospace,Consolas,monospace;padding:32px}
h1{font-size:18px;color:#7cc7ff;margin:0 0 4px}.dim{color:#666}a{color:#7cc7ff}</style>
<h1>%(banner)s</h1><p class="dim">request captured.</p>
<p>host: <b>%(host)s</b><br>path: <b>%(path)s</b></p>
<p><a href="/">browse local files</a></p>"""


# --------------------------------------------------------------------------
# 8080 log console (logserver.py compatible + API)
# --------------------------------------------------------------------------
DASHBOARD = """<!doctype html><html><head><meta charset=utf-8>
<title>%(banner)s log</title>
<style>
:root{--fg:#dcdcdc;--dim:#6f6f6f;--bg:#0e0e0e;--card:#171717;--brd:#2a2a2a;--acc:#7cc7ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
 font:13px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}
header{padding:12px 16px;border-bottom:1px solid var(--brd);display:flex;gap:14px;
 align-items:center;flex-wrap:wrap;position:sticky;top:0;background:var(--bg);z-index:5}
h1{font-size:14px;margin:0;color:var(--acc);font-weight:600}
button{background:var(--card);color:var(--fg);border:1px solid var(--brd);border-radius:5px;
 padding:4px 9px;cursor:pointer;font:inherit}button.on{border-color:var(--acc);color:var(--acc)}
input{background:var(--card);border:1px solid var(--brd);border-radius:5px;color:var(--fg);
 padding:4px 8px;font:inherit;width:220px}
main{padding:10px 16px}
table{border-collapse:collapse;width:100%%}td{padding:2px 8px 2px 0;vertical-align:top;
 border-bottom:1px solid #1c1c1c;white-space:nowrap}
td.txt{white-space:pre-wrap;word-break:break-all;width:100%%}
i.k{font-style:normal;color:#000;border-radius:3px;padding:0 5px;font-size:11px}
.k-dns{background:#5b8dd6}.k-http{background:#57b57a}.k-https{background:#3fc1b0}
.k-tls{background:#d68f5b}.k-xlog{background:#c9c25b}.k-dhcp{background:#b57ad6}
.k-sys{background:#888}
.hide{display:none}footer{color:var(--dim);padding:8px 16px 30px}
a{color:var(--acc)}
</style></head><body>
<header>
 <h1>%(banner)s</h1>
 <div id="filters"></div>
 <input id="q" placeholder="filter text…">
 <button id="follow" class="on">follow</button>
 <button id="clear">clear</button>
 <span id="stat" class="hide"></span>
 <a href="/log.txt" target="_blank">8080 log</a>
 <a href="/intercept.txt" target="_blank">intercepted log</a>
 <a href="/api/entries" target="_blank">json</a>
</header>
<main><table id="t"></table></main>
<footer id="foot">waiting for traffic…</footer>
<script>
const kinds=['all','dns','http','https','tls','xlog','dhcp','sys'];
let active='all', since=0, follow=true, seen=new Set();
const qs=k=>document.getElementById(k);
function paintFilters(){qs('filters').innerHTML=kinds.map(k=>
 `<button class="f ${k==active?'on':''}" data-k="${k}">${k}</button>`).join('');
 [...document.querySelectorAll('.f')].forEach(b=>b.onclick=()=>{active=b.dataset.k;paintFilters();render();});}
let rows=[];
function cls(k){return 'k-'+(k||'sys')}
function render(){
 const q=qs('q').value.toLowerCase();
 const t=qs('t'); t.innerHTML='';
 let n=0;
 for(const e of rows){
  if(active!=='all'&&e.kind!==active) continue;
  if(q&&!JSON.stringify(e).toLowerCase().includes(q)) continue;
  n++;
  const tr=document.createElement('tr');
  tr.innerHTML=`<td class="dim">${e.ts}</td><td><i class="k ${cls(e.kind)}">${e.kind}</i></td>
   <td class="txt">${e.text.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</td>`;
  t.appendChild(tr);
 }
 qs('foot').textContent=`${n} shown / ${rows.length} buffered`;
}
async function poll(){
 try{
  const r=await fetch('/api/entries?since='+since+'&limit=400');
  const j=await r.json();
  if(j.entries.length){ for(const e of j.entries){ if(!seen.has(e.id)){seen.add(e.id);rows.push(e);} } since=j.next;
   if(rows.length>800) rows=rows.slice(-800);
   if(follow){render(); const el=document.querySelector('main'); el.scrollIntoView(false);} }
 }catch(e){}
}
qs('follow').onclick=e=>{follow=!follow;e.target.classList.toggle('on',follow)};
qs('clear').onclick=()=>{rows=[];render()};
qs('q').oninput=render;
paintFilters();
setInterval(poll,700); poll();
</script></body></html>"""


class LogHttpServer(ExclusiveBind, http.server.ThreadingHTTPServer):
    daemon_threads = True


def _int_arg(q: dict, key: str, default: int, lo: int = 0, hi: int = 1 << 30) -> int:
    """A hand-typed ?since=abc must return JSON, not close the socket."""
    try:
        return max(lo, min(int(str(q.get(key, [""])[0]).strip() or default), hi))
    except (TypeError, ValueError):
        return default


class ConsoleHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AllInOne-log/" + VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        try:
            self._route_get()
        except Exception as e:                  # never drop the connection silently
            log_add("sys", f"console error on {self.path}: {type(e).__name__}: {e}")
            try:
                self._text(400, f"bad request: {type(e).__name__}: {e}")
            except OSError:
                pass

    def _route_get(self):
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query)
        if p.path == "/log":                        # logserver.py compatible
            line = q.get("line", [""])[0]
            if line:
                log_raw(line, "xbox")
            self._text(200, "ok")
        elif p.path == "/log.txt":
            # logserver.py compatibility: exactly what the console posted to :8080
            self._text(200, LOG.text() if LOG else "")
        elif p.path in ("/intercept.txt", "/log-intercepted.txt"):
            # everything the interceptor saw (this is the log.txt file on disk)
            self._text(200, LOG.intercept_text() if LOG else "")
        elif p.path == "/api/entries":
            since = _int_arg(q, "since", 0)
            limit = _int_arg(q, "limit", 500, lo=1, hi=5000)
            kind = q.get("kind", [""])[0]
            needle = q.get("q", [""])[0]
            ent = LOG.query(since, limit, kind, needle) if LOG else []
            nxt = ent[-1]["id"] if ent else since
            self._json(200, {"entries": ent, "next": nxt,
                             "total": LOG.next_id if LOG else 0})
        elif p.path == "/api/stats":
            self._json(200, LOG.stats() if LOG else {})
        elif p.path == "/health":
            self._json(200, {"ok": True, "version": VERSION, "last_id": LOG.next_id if LOG else 0})
        elif p.path in ("/", "/index.html"):
            body = DASHBOARD % {"banner": BANNER}
            self._text(200, body, "text/html; charset=utf-8")
        elif p.path == "/favicon.ico":
            self._text(204, "")
        else:
            self._text(404, "use /  /log?line=…  /log.txt  /api/entries  /api/stats")

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        body = self.rfile.read(min(n, MAX_BODY)) if n else b""
        if p.path in ("/log", "/"):
            text = body.decode("utf-8", "replace").strip()
            if text:
                log_raw(text, "xbox-post")
            self._text(200, "ok")
        else:
            self._text(404, "no")

    def _text(self, code: int, body: str, ctype="text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")   # the Xbox needs this
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if data:
            try:
                self.wfile.write(data)
            except OSError:
                pass

    def _json(self, code: int, obj):
        self._text(code, json.dumps(obj, ensure_ascii=False), "application/json")


# --------------------------------------------------------------------------
# optional DHCP server: makes every device on the LAN use us as DNS
# --------------------------------------------------------------------------
class DhcpServer(threading.Thread):
    def __init__(self, ip: str, pool: str, mask: str = "255.255.255.0",
                 lease: int = 3600, bind: str = "0.0.0.0", port: int = 67):
        super().__init__(daemon=True, name=f"dhcp:{port}")
        self.ip, self.mask, self.lease = ip, mask, lease
        self.stop_flag = threading.Event()
        self.leases: dict[str, tuple[str, float]] = {}
        self.start_octet, self.end_octet = self._parse_pool(pool)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tune_listen_sock(self.sock, udp=True)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind((bind, port))

    def _parse_pool(self, pool: str) -> tuple[int, int]:
        try:
            a, _, b = pool.partition("-")
            return int(a.split(".")[-1]), int(b.split(".")[-1])
        except Exception:
            return 200, 250

    def _alloc(self, mac: str) -> str:
        base = self.ip.rsplit(".", 1)[0]
        now = time.time()
        if mac in self.leases and now - self.leases[mac][1] < self.lease:
            return self.leases[mac][0]
        used = {v[0] for v in self.leases.values()}
        for o in range(self.start_octet, self.end_octet + 1):
            cand = f"{base}.{o}"
            if cand not in used and cand != self.ip:
                self.leases[mac] = (cand, now)
                return cand
        return f"{base}.{self.end_octet}"

    def run(self):
        while not self.stop_flag.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError as e:
                if self.stop_flag.is_set():
                    break
                err = getattr(e, "winerror", None) or e.errno
                if err in (10038, 9, 10022):
                    break
                continue                      # see DnsUdpServer.run
            m = self._parse(data)
            if not m:
                continue
            mac = ":".join(f"{b:02x}" for b in m["chaddr"])
            msgtype = m["opts"].get(53, b"\x00")[0]
            yiaddr = self._alloc(mac)
            name = "offer" if msgtype == 1 else ("ack" if msgtype == 3 else None)
            if name is None:
                continue
            reply = self._build(m["xid"], m["chaddr"], yiaddr, 2 if msgtype == 1 else 5)
            try:
                self.sock.sendto(reply, ("255.255.255.255", 68))
            except OSError:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    pass
            log_add("dhcp", f"{mac} {name} {yiaddr} (dns={self.ip} router={self.ip} "
                            f"lease={self.lease}s)", src=addr[0], host=mac)

    def _parse(self, data: bytes):
        if len(data) < 240 or data[0] != 1 or data[236:240] != b"\x63\x82\x53\x63":
            return None
        hlen = data[2] or 6
        opts, i = {}, 240
        while i < len(data):
            code = data[i]
            if code == 0:
                i += 1
                continue
            if code == 255:
                break
            if i + 1 >= len(data):
                break
            ln = data[i + 1]
            opts[code] = data[i + 2:i + 2 + ln]
            i += 2 + ln
        return {"xid": data[4:8], "chaddr": data[28:28 + min(hlen, 16)], "opts": opts}

    def _build(self, xid: bytes, chaddr: bytes, yiaddr: str, msgtype: int) -> bytes:
        p = bytearray(240)
        p[0], p[1], p[2] = 2, 1, 6
        p[4:8] = xid
        p[10:12] = b"\x80\x00"                      # broadcast reply
        p[16:20] = socket.inet_aton(yiaddr)
        p[20:24] = socket.inet_aton(self.ip)
        p[28:28 + len(chaddr)] = chaddr
        p[236:240] = b"\x63\x82\x53\x63"
        o = bytearray()

        def add(code, val):
            o.extend(bytes([code, len(val)]))
            o.extend(val)

        add(53, bytes([msgtype]))
        add(54, socket.inet_aton(self.ip))
        add(1, socket.inet_aton(self.mask))
        add(3, socket.inet_aton(self.ip))            # router -> us
        add(6, socket.inet_aton(self.ip))            # DNS    -> us
        add(51, struct.pack(">I", self.lease))
        add(12, BANNER.encode())
        add(255, b"")
        return bytes(p) + bytes(o)

    def stop(self):
        self.stop_flag.set()
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# startup / teardown
# --------------------------------------------------------------------------
def bind_report(name: str, host: str, port: int, proto: str = "tcp") -> bool:
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    s = socket.socket(socket.AF_INET, kind)
    tune_listen_sock(s)
    try:
        s.bind((host, port))
        print(f"  [ok]   {name:7s} {proto} {host}:{port}")
        return True
    except OSError as e:
        hint = ""
        if e.errno in (10013, 13):
            hint = "  (held by another service / http.sys URL reservation -- " \
                   "stop it or use another port)"
        elif e.errno in (10048, 98):
            hint = "  (already in use)"
        print(f"  [FAIL] {name:7s} {proto} {host}:{port}: {e}{hint}")
        return False
    finally:
        s.close()


def firewall_rules(ports=(53, 80, 443, 8080, 67)) -> None:
    for p in ports:
        for proto in ("UDP", "TCP"):
            cmd = (f'netsh advfirewall firewall add rule name="allinone-{p}-{proto}" '
                   f"dir=in action=allow protocol={proto} localport={p}")
            os.system(cmd)


def set_system_dns(ip: str, action: str = "set") -> None:
    """Point (or unpoint) this PC's resolvers at us.  Needs admin."""
    print("  netsh needs an elevated shell; output follows.")
    if action == "set":
        os.system(f'netsh interface ip set dns name="Ethernet 5" static {ip} primary')
        os.system(f'netsh interface ip add dns name="Ethernet 5" {ip} index=1')
    else:
        os.system('netsh interface ip set dns name="Ethernet 5" source=dhcp')


def selftest() -> int:
    """Built-in checks that need no privileged ports."""
    ok = True
    print("== selftest ==")
    # 1. cert generation + a real TLS handshake against it
    t0 = time.time()
    cert, key = ensure_cert(force=True, log=lambda m: None)
    print(f"  cert generated in {time.time() - t0:.1f}s -> {cert}")
    try:
        ctx = _tls_context((cert, key))
        srv = CaptureServer(("127.0.0.1", 0), CaptureHandler, scheme="https",
                            webroot="", mode="page", page=b"ok", cfg_ip="127.0.0.1",
                            tls=(cert, key))
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.load_verify_locations(cert)
        cctx.check_hostname = True
        cctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection(("127.0.0.1", port), 5) as raw:
            with cctx.wrap_socket(raw, server_hostname="localhost") as tls:
                tls.sendall(b"GET /selftest HTTP/1.1\r\nHost: localhost\r\n"
                            b"Connection: close\r\n\r\n")
                data = tls.recv(4096)
        good = b"200" in data.split(b"\r\n")[0]
        print(f"  TLS handshake+verify (our cert as CA, check_hostname): "
              f"{'PASS' if good else 'FAIL'}  {data.split(chr(13).encode())[0].decode()}")
        ok &= good
        srv.shutdown()
    except Exception as e:
        print(f"  TLS test FAILED: {e!r}")
        ok = False
    # 2. dns_reply contract
    r = dns_reply(DNSRecord.question("example.test"), "192.168.1.146", None)
    good = str(r.rr[0].rdata) == "192.168.1.146" and r.rr[0].ttl == 0
    print(f"  dns_reply A -> {r.rr[0].rdata} ttl={r.rr[0].ttl}: {'PASS' if good else 'FAIL'}")
    ok &= good
    r6 = dns_reply(DNSRecord.question("example.test", "AAAA"), "192.168.1.146", None)
    good = len(r6.rr) == 0 and r6.header.rcode == 0
    print(f"  dns_reply AAAA -> NODATA: {'PASS' if good else 'FAIL'}")
    ok &= good
    print("== selftest:", "PASS" if ok else "FAIL", "==")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="all-in-one DNS hijack + web capture + log console")
    p.add_argument("--ip", default=None, help="address handed out for every A query (default: LAN IP)")
    p.add_argument("--bind", default="0.0.0.0", help="bind address for all listeners")
    p.add_argument("--dns-port", type=int, default=53)
    p.add_argument("--http-port", type=int, default=80)
    p.add_argument("--https-port", type=int, default=443)
    p.add_argument("--log-port", type=int, default=8080)
    p.add_argument("--dhcp", action="store_true", help="also run a DHCP server (hijacks the whole LAN)")
    p.add_argument("--dhcp-pool", default=None, help="e.g. 192.168.1.200-192.168.1.250")
    p.add_argument("--dhcp-lease", type=int, default=3600)
    p.add_argument("--ttl", type=int, default=0, help="TTL on synthetic answers (0 = no caching)")
    p.add_argument("--aaaa", choices=("nodata", "redirect"), default="nodata")
    p.add_argument("--upstream", default="", help="comma list, e.g. 8.8.8.8,1.1.1.1")
    p.add_argument("--bypass", action="append", default=[],
                   help="domain (or suffix) to resolve for real via --upstream; repeatable")
    p.add_argument("--forward-all", action="store_true",
                   help="relay every query upstream and just log it (pure recon mode)")
    p.add_argument("--fail-open", action="store_true",
                   help="if the upstream is dead, still answer with --ip instead of SERVFAIL")
    p.add_argument("--webroot", default=DEFAULT_WEBROOT,
                   help="directory served for matching paths "
                        "(default: lan_dns_web\\webroot)")
    p.add_argument("--mode", choices=("auto", "serve", "redirect", "page", "empty"),
                   default="auto", help="auto = serve files if present else redirect http->https")
    p.add_argument("--redirect-template", default="",
                   help="redirect target for paths that don't match a file; placeholders "
                        "{ip} {port} {host} {path}. Default 'http://{ip}[:{port}]{path}' = us, "
                        "same scheme. 'https://{host}{path}' preserves the hostname (gives you "
                        "the SNI, but needs the client to keep using our DNS and to accept our cert)")
    p.add_argument("--cert", default=DEFAULT_CERT)
    p.add_argument("--key", default=DEFAULT_KEY)
    p.add_argument("--regen-cert", action="store_true")
    p.add_argument("--san-file", default="", help="extra SAN hostnames, one per line")
    p.add_argument("--legacy-tls", action="store_true",
                   help="allow TLS1.0/1.1 + legacy ciphers (old consoles)")
    p.add_argument("--logfile", default=DEFAULT_LOGFILE,
                   help="port-8080 receiver log: ONLY what is posted to /log?line= "
                        "or POST /, appended verbatim (logserver.py behaviour)")
    p.add_argument("--intercept-logfile", default=None,
                   help="where DNS/HTTP/HTTPS/TLS/DHCP/sys lines go "
                        "(default: log.txt beside --logfile)")
    p.add_argument("--no-dns", action="store_true")
    p.add_argument("--no-http", action="store_true")
    p.add_argument("--no-https", action="store_true")
    p.add_argument("--no-logsrv", action="store_true")
    p.add_argument("--firewall", action="store_true", help="add inbound netsh rules (needs admin)")
    p.add_argument("--set-dns", action="store_true",
                   help="point this PC's own resolver at us (needs admin)")
    p.add_argument("--restore-dns", action="store_true")
    p.add_argument("--selftest", action="store_true")
    return p


def main(argv=None) -> int:
    global LOG
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()

    ip = args.ip or local_ip()
    LOG = Log(os.path.abspath(args.logfile),
              os.path.abspath(args.intercept_logfile) if args.intercept_logfile else None)
    cfg = DnsConfig(ip, args.ttl, args.aaaa, [u.strip() for u in args.upstream.split(",") if u.strip()],
                    args.bypass, args.forward_all, fail_closed=not args.fail_open)

    if args.firewall:
        firewall_rules()
    if args.restore_dns:
        set_system_dns(ip, "restore")
    if args.set_dns:
        set_system_dns(ip, "set")

    print(f"\n  {BANNER} v{VERSION}")
    print(f"  redirect address : {ip}      admin: {'yes' if is_admin() else 'no (not required)'}")
    print(f"  8080 receiver log: {LOG.path}   (only /log?line= and POST /)")
    print(f"  intercepted log  : {LOG.intercept}   (DNS, HTTP, HTTPS, TLS, DHCP, sys)")
    print(f"  webroot          : {args.webroot}")
    print(f"  dns policy       : {'FORWARD-ALL upstream=' + ','.join(cfg.upstreams) if cfg.forward_all else 'redirect every A -> ' + ip}"
          + (f"   bypass={cfg.bypass}" if cfg.bypass else ""))
    print("\n  bind check:")
    plan = []
    if not args.no_dns:
        plan += [("dns", 53, "udp"), ("dns", 53, "tcp")]
    if not args.no_http:
        plan.append(("http", args.http_port, "tcp"))
    if not args.no_https:
        plan.append(("https", args.https_port, "tcp"))
    if not args.no_logsrv:
        plan.append(("log", args.log_port, "tcp"))
    if args.dhcp:
        plan.append(("dhcp", 67, "udp"))
    free = {}
    for name, port, proto in plan:
        actual = args.dns_port if name == "dns" else port
        free[(name, proto)] = bind_report(name, args.bind, actual, proto)

    threads = []
    # ---- DNS
    if not args.no_dns and free.get(("dns", "udp")):
        try:
            u = DnsUdpServer(args.bind, args.dns_port, cfg)
            u.start()
            threads.append(u)
            log_add("sys", f"DNS/udp up on {args.bind}:{args.dns_port} -> {ip}")
        except OSError as e:
            print(f"  [FAIL] DNS/udp start: {e}")
    if not args.no_dns and free.get(("dns", "tcp")):
        try:
            t = DnsTcpServer((args.bind, args.dns_port), DnsTcpHandler)
            t.dns_cfg = cfg
            threading.Thread(target=t.serve_forever, daemon=True, name="dns-tcp").start()
            threads.append(t)
            log_add("sys", f"DNS/tcp up on {args.bind}:{args.dns_port} -> {ip}")
        except OSError as e:
            print(f"  [FAIL] DNS/tcp start: {e}")
    # ---- HTTP / HTTPS
    tls_paths = None
    if not args.no_https and free.get(("https", "tcp")):
        names = SAN_NAMES + [n.strip() for n in
                             (open(args.san_file, encoding="utf-8").read().split() if args.san_file
                              and os.path.isfile(args.san_file) else [])]
        tls_paths = ensure_cert(args.cert, args.key, names, [ip, "127.0.0.1", "::1"],
                                force=args.regen_cert, log=lambda m: print("  " + m))
    # Redirects point at US, same scheme -- not at the requested name, and not
    # upgraded to https (a device that doesn't trust our cert would get nothing).
    redirect_template = args.redirect_template or (
        "http://{ip}" + ("" if args.http_port == 80 else ":{port}") + "{path}")
    print(f"  redirect target  : {redirect_template}")
    for name, port, scheme in (("http", args.http_port, "http"), ("https", args.https_port, "https")):
        if scheme == "http" and args.no_http:
            continue
        if scheme == "https" and args.no_https:
            continue
        if not free.get((name, "tcp")):
            continue
        srv = CaptureServer(
            (args.bind, port), CaptureHandler, scheme=scheme,
            webroot=os.path.abspath(args.webroot), mode=args.mode,
            page=DEFAULT_PAGE % {"banner": BANNER, "host": ip, "path": "/"},
            redirect_template=redirect_template, cfg_ip=ip,
            tls=tls_paths if scheme == "https" else None, legacy=args.legacy_tls)
        threading.Thread(target=srv.serve_forever, daemon=True, name=f"{scheme}:{port}").start()
        threads.append(srv)
        log_add("sys", f"{scheme.upper()} up on {args.bind}:{port} mode={args.mode} "
                       f"webroot={args.webroot}")
        if scheme == "https":
            import ssl as _s
            # server.crt may hold a full chain (leaf + CA); PEM_cert_to_DER_cert
            # only handles a single PEM block, so take the first certificate.
            _pem_all = open(tls_paths[0]).read()
            _first = _pem_all.split("-----END CERTIFICATE-----", 1)[0] + "-----END CERTIFICATE-----\n"
            der = _s.PEM_cert_to_DER_cert(_first)
            fp = hashlib.sha256(der).hexdigest()
            print(f"  cert sha256: {':'.join(fp[i:i+4] for i in range(0, 64, 4))[:47]}…")
    # ---- log console
    if not args.no_logsrv and free.get(("log", "tcp")):
        lsrv = LogHttpServer((args.bind, args.log_port), ConsoleHandler)
        threading.Thread(target=lsrv.serve_forever, daemon=True, name="logsrv").start()
        threads.append(lsrv)
        log_add("sys", f"LOG console up on {args.bind}:{args.log_port}")
    # ---- dhcp
    if args.dhcp and free.get(("dhcp", "udp")):
        net = ip.rsplit(".", 1)[0]
        pool = args.dhcp_pool or f"{net}.200-{net}.250"
        try:
            d = DhcpServer(ip, pool, lease=args.dhcp_lease)
            d.start()
            threads.append(d)
            log_add("sys", f"DHCP up: pool {pool}, dns+router {ip}")
            print(f"  [ok]   DHCP pool {pool} -> dns/router {ip}")
        except OSError as e:
            print(f"  [FAIL] DHCP start: {e}  (stop the Windows 'DHCP Server' service, or "
                  f"another DHCP daemon)")

    if not threads:
        print("\n  nothing started -- every port failed.  Use --http-port/--https-port/"
              "--dns-port/--log-port to move off a busy port.\n")
        return 2

    print("\n  live:")
    print(f"    DNS      {ip}:{args.dns_port}   (point clients here, or use --dhcp)")
    print(f"    HTTP     http://{ip}:{args.http_port}/       (any Host)")
    print(f"    HTTPS    https://{ip}:{args.https_port}/      (self-signed)")
    print(f"    console  http://{ip}:{args.log_port}/  |  /log.txt  |  /api/entries")
    print(f"    receiver http://{ip}:{args.log_port}/log?line=<text>   (logserver.py compatible)")
    print("\n  Ctrl+C to stop.\n")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n  stopping…")
        for t in threads:
            s = getattr(t, "shutdown", None)
            try:
                if s and not isinstance(t, (DnsUdpServer, DhcpServer)):
                    s()
            except Exception:
                pass
            try:
                t.stop()
            except Exception:
                pass
        time.sleep(0.4)
        print(f"  log written to {LOG.path}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
