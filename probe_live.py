#!/usr/bin/env python3
"""Live probe: starts app.py, waits for readiness, exercises every service,
prints what really came back, then stops it.

    python probe_live.py                 # standard ports 53/80/443/8080
    python probe_live.py --alt           # unprivileged 5353/8081/8443/8080
    python probe_live.py --ip 192.168.1.146 --webroot ..
"""
import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def wait_http(host, port, path="/health", timeout=25):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(f"http://{host}:{port}{path}", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def https_raw(port, path, host, sni=None, cacert=None):
    """Raw TLS so the SNI, hostname check and cert source are all explicit."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if cacert:
        ctx.load_verify_locations(cacert)
        ctx.check_hostname = True
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    s = socket.create_connection(("127.0.0.1", port), 6)
    t = ctx.wrap_socket(s, server_hostname=sni or host)
    try:
        t.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            c = t.recv(4096)
            if not c:
                break
            data += c
    finally:
        t.close()
    return int(data.split(b" ")[1]), data[:120]


def raw(port, path, host, method="GET", body=None, cap=200):
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=6)
    c.request(method, path, body=body, headers={"Host": host})
    r = c.getresponse()
    data = r.read()
    out = (r.status, data if cap is None else data[:cap], dict(r.getheaders()))
    c.close()
    return out


def dns_probe(port, name, qtype="A"):
    from dnslib import DNSRecord
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    s.sendto(DNSRecord.question(name, qtype).pack(), ("127.0.0.1", port))
    data, _ = s.recvfrom(4096)
    s.close()
    r = DNSRecord.parse(data)
    answers = [str(rr.rdata) for rr in r.rr]
    return answers or ["(nodata, rcode=%d)" % r.header.rcode]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alt", action="store_true")
    ap.add_argument("--ip", default=None)
    ap.add_argument("--webroot", default=os.path.join(HERE, "webroot"))
    ap.add_argument("--extra", nargs="*", default=[])
    a = ap.parse_args()
    # 5353 is taken by mDNS on Windows -- 5354 keeps the alt run clean
    dp, hp, sp, lp = (5354, 8081, 8443, 8080) if a.alt else (53, 80, 443, 8080)
    logfile = os.path.join(HERE, "logs", "xbox-log-received.log")
    before = os.path.getsize(logfile) if os.path.isfile(logfile) else 0
    interfile = os.path.join(HERE, "logs", "log.txt")
    ibefore = os.path.getsize(interfile) if os.path.isfile(interfile) else 0
    cmd = [sys.executable, os.path.join(HERE, "app.py"),
           "--dns-port", str(dp), "--http-port", str(hp), "--https-port", str(sp),
           "--log-port", str(lp), "--webroot", os.path.abspath(a.webroot),
           "--logfile", logfile] + (["--ip", a.ip] if a.ip else []) + a.extra
    print("$", " ".join(cmd), "\n")
    p = subprocess.Popen([sys.executable, "-u"] + cmd[1:], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                         errors="replace")
    ok = wait_http("127.0.0.1", lp)
    print(f"--- startup output (readiness on :{lp}: {'yes' if ok else 'NO'}) ---")
    time.sleep(0.4)
    try:
        print("--- probes ---")
        for name in ("www.xboxlive.com", "example.test"):
            print(f"  DNS  {name:20s} A   -> {dns_probe(dp, name)}")
        print(f"  DNS  www.xboxlive.com    AAAA-> {dns_probe(dp, 'www.xboxlive.com', 'AAAA')}")
        print(f"  HTTP GET /xbox-chakra-stage-test-v129.html -> "
              f"{raw(hp, '/xbox-chakra-stage-test-v129.html', 'evil.example')[0]}")
        st, _, hd = raw(hp, "/definitely-missing-path", "evil.example")
        loc = hd.get("Location", "-")
        print(f"  HTTP GET /definitely-missing-path -> {st} Location: {loc}"
              f"   {'OK (us, http)' if loc.startswith('http://192.168.1.146') else 'WRONG TARGET'}")
        loc2 = raw(hp, "/ncsi.txt", "www.msftncsi.com")[2].get("Location", "-")
        print(f"  HTTP GET /ncsi.txt (Host www.msftncsi.com) -> Location: {loc2}")
        have = os.path.isfile(os.path.join(a.webroot, "ncsi.txt"))
        st2, body2, _ = raw(hp, "/ncsi.txt", "192.168.1.146")
        print(f"  following it (Host = our IP) -> {st2} {body2[:20]!r}"
              f"   (webroot/ncsi.txt {'exists -> should be its bytes' if have else 'absent -> landing page'})")
        st3, _, _ = raw(hp, "/anything-else", "192.168.1.146")
        print(f"  non-probe path on our IP -> {st3} (200 = no redirect loop)")
        st, body, _ = raw(hp, "/", "evil.example")
        print(f"  HTTP GET / (dir listing? {st}) -> {body[:60]!r}")
        try:
            print(f"  HTTPS GET /lab, SNI=www.xboxlive.com, cert unchecked -> "
                  f"{https_raw(sp, '/lab', 'www.xboxlive.com')[0]}")
        except Exception as e:
            print(f"  HTTPS unchecked FAILED: {type(e).__name__}: {e}")
        try:
            print(f"  HTTPS bad name, our CA + check_hostname -> "
                  f"{https_raw(sp, '/lab', 'nope.invalid', cacert=os.path.join(HERE, 'certs', 'server.crt'))[0]}"
                  f"  (should have raised)")
        except ssl.SSLCertVerificationError:
            print("  HTTPS bad name, our CA + check_hostname -> rejected "
                  "(SAN list is doing the work)")
        try:
            print(f"  HTTPS verified against our CA (check_hostname=True) -> "
                  f"{https_raw(sp, '/lab', 'www.xboxlive.com',
                               cacert=os.path.join(HERE, 'certs', 'server.crt'))[0]}")
        except Exception as e:
            print(f"  HTTPS verified -> {type(e).__name__}: {e}")
        marker = "PROBE-" + str(int(time.time()))
        print(f"  LOG  /log?line={marker} -> {raw(lp, '/log?line=' + marker, '127.0.0.1')[0]}")
        st, body, _ = raw(lp, "/log.txt", "127.0.0.1", cap=None)
        print(f"  LOG  /log.txt ({len(body)} bytes) contains marker: {marker.encode() in body}")
        st, body, _ = raw(lp, "/api/entries?limit=3", "127.0.0.1", cap=None)
        print(f"  LOG  /api/entries -> {st}, {json.loads(body)['total']} total buffered")
        print(f"  LOG  / (dashboard) -> {raw(lp, '/', '127.0.0.1')[0]}")
        time.sleep(0.8)
        print("--- tailing both logs (new lines only) ---")
        tail = {}
        for label, path, pos in (("xbox-log-received.log", logfile, before),
                                 ("log.txt", interfile, ibefore)):
            try:
                with open(path, "rb") as f:
                    f.seek(pos)
                    data = f.read().decode("utf-8", "replace")
            except OSError:
                data = ""
            tail[label] = [ln for ln in data.splitlines() if ln.strip()]
            print(f"   {label} -> {len(tail[label])} new line(s)")
            for ln in tail[label][-8:]:
                print("     " + ln)

        print("--- verification ---")
        fails = []
        # 1. every new line in the receiver log must be raw 8080 content
        bad = [ln for ln in tail["xbox-log-received.log"]
               if ln.startswith("[") and "]" in ln[:40]]
        if bad:
            fails.append(f"{len(bad)} interceptor line(s) leaked into "
                         f"xbox-log-received.log, e.g. {bad[0][:60]!r}")
        if marker not in "\n".join(tail["xbox-log-received.log"]):
            fails.append("the /log?line= marker did not land in "
                         "xbox-log-received.log")
        # 2. the intercepted events must be in log.txt, not the receiver file
        for needle in ("[DNS ", "[HTTP ", "[SYS ", "[TLS ", "[HTTPS]"):
            if not any(needle in ln for ln in tail["log.txt"]):
                fails.append(f"no {needle.strip()}] line in log.txt")
        if marker in "\n".join(tail["log.txt"]):
            fails.append("the 8080 marker leaked into log.txt")
        if fails:
            for f in fails:
                print("   FAIL " + f)
        else:
            print("   PASS  xbox-log-received.log holds only 8080 lines")
            print("   PASS  log.txt holds the interceptor lines")
            print("   PASS  neither file contains the other's lines")
    finally:
        p.terminate()
        try:
            out = p.communicate(timeout=8)[0]
        except subprocess.TimeoutExpired:
            p.kill(); out = p.communicate()[0]
        print("--- app stdout (startup) ---")
        print("\n".join((out or "").splitlines()[:28]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
