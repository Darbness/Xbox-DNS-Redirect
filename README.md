# all-in-one DNS hijack + web capture + log console

One process. Point the Xbox (or anything else) at this PC for DNS and every name
it resolves lands on `app.py` instead — ports 80 and 443 both answer and log, and
:8080 stays the `logserver.py`-compatible log receiver your harness already posts to.

```
python app.py                       # 53/80/443/8080, serves ..\ as the webroot
python app.py --dhcp                # also hand out our DNS via DHCP (whole LAN)
python app.py --forward-all         # don't hijack: relay + log every query (recon)
python app.py --dns-port 5354 --http-port 8081 --https-port 8443   # unprivileged run
python app.py --selftest            # no ports touched, 10-second sanity check
```

## What each port does

| Port | Service | Behaviour |
|------|---------|-----------|
| 53 udp+tcp | DNS | `A` → `--ip` (TTL 0). `AAAA` → NODATA so clients fall back to IPv4. `--bypass dom`/`--forward-all` queries go to `--upstream` for real. Everything logged. |
| 80 | HTTP | Any Host, any path. Serves files out of `--webroot` if they exist, otherwise 302s to **`http://<our ip>[:port]<path>`** — our own address, not the requested hostname (a cached answer, DoH lookup or hardcoded IP would otherwise walk straight out to the real server) and deliberately still `http://` (a redirect to our self-signed TLS port fails the handshake on any device that doesn't trust our cert). The follow-up, which arrives with Host = our IP, is answered locally — connectivity probes get their canned answer so the device still reports online. |
| 443 | HTTPS | Same handler over TLS with an auto-generated self-signed cert. Logs the SNI on success **and** on failed handshakes (a device that rejects the cert still tells you the hostname it wanted). |
| 8080 | console | `/log?line=<text>` and `POST /` append verbatim (logserver.py compatible), `/log.txt` raw dump, `/` live dashboard, `/api/entries`, `/api/stats`, `/health`. |
| 67 | DHCP | `--dhcp`: OFFER/ACK with `--ip` as router **and** DNS, so every device on the LAN resolves through us without touching any client config. |

## Logs — two files, on purpose (both under `lan_dns_web\logs\`)

* `logs\xbox-log-received.log` — **only** what arrives on port 8080: every `/log?line=…`
  and `POST /` body, appended byte-for-byte with no prefix and no timestamp, exactly as
  `logserver.py` did. Your harness and any parser you already have keep working
  unchanged, and nothing else ever lands in this file.
* `logs\log.txt` — everything this server observed itself, one line per event, prefixed
  `[timestamp] [KIND]`, kind ∈ `DNS|HTTP|HTTPS|TLS|DHCP|SYS`. `TLS` lines carry the SNI
  and the certificate served. Override with `--intercept-logfile`.
* `logs\log.txt.jsonl` — structured `{id,ts,kind,text,src,meta}` mirror of the interceptor
  events, for the dashboard and `/api/entries`.

In the browser: `http://<ip>:8080/log.txt` is the 8080 receiver file,
`http://<ip>:8080/intercept.txt` is the intercepted-events file.

Example lines:

```
[2026-10-16 12:18:58.137] [DNS  ] 192.168.1.50 q=www.xboxlive.com A -> 192.168.1.146 [redirect]
[2026-10-16 12:18:58.178] [HTTP ] 192.168.1.50:53097 GET /xbox-chakra-stage-test-v129.html HTTP/1.1 host=evil.example sni=- Host=evil.example body=0B -> 200 file:xbox-chakra-stage-test-v129.html (9.7K)
[2026-10-16 12:18:58.212] [TLS  ] 192.168.1.50:53101 TLS handshake FAILED sni=www.xboxlive.com (SSLError: ... bad certificate)
```

### Redirect target: our IP, same scheme

```
GET http://www.msftncsi.com/ncsi.txt          (no file at webroot/ncsi.txt)
  → 302 Location: http://192.168.1.146/ncsi.txt      (arrives with Host = our IP)
  → 200 landing page                                  (still no file -> nothing invented)

GET http://www.msftncsi.com/ncsi.txt          (webroot/ncsi.txt exists)
  → 200 <that file, byte for byte>                    (no redirect at all)
```

Two rules, both learned the hard way:

* **Never `<requested host>`.** A `Location: https://www.msftncsi.com/…` only comes
  back to us while the client keeps using our DNS; one cached answer, a DoH lookup
  or a hardcoded IP and the device goes straight out to the real service.
* **Never upgrade to `https://`.** A plain-HTTP fetch redirected to our self-signed
  TLS port dies at the handshake, so a device that doesn't trust our cert gets
  nothing at all — no content, just a dead connection. Staying on `http://` means
  the follow-up completes.

Because the target is our own address, a naive redirect would loop forever, so the
follow-up (Host = our IP) is answered locally: it serves `--webroot` again, and if
the path still has no file it gets the landing page. Nothing is ever invented — the
server only sends bytes that exist under `--webroot`.

So if you want a device's connectivity check to succeed (the Xbox asks for
`/ncsi.txt` and `/xboxncsi.txt`), **put those files in the webroot** — with the
substance you decide, e.g. the folder above `app.py`:

    echo Microsoft NCSI > ncsi.txt
    echo Microsoft NCSI > xboxncsi.txt

They are then served verbatim to any Host, no redirect involved.

`--redirect-template` overrides this — placeholders are `{ip} {port} {host} {path}`,
e.g. `'https://{host}{path}'` if you deliberately want hostname-preserving redirects
(you get the SNI on the TLS leg, but you need the client on our DNS *and* trusting
our cert).

## Getting the client to use us

1. **Console/client DNS setting** (cleanest): set the Xbox's DNS to `192.168.1.146`.
   Or point this PC at itself: `python app.py --set-dns` (netsh, needs an elevated
   shell; `--restore-dns` puts it back to DHCP).
2. **DHCP** (`--dhcp`): no client config at all — every device that renews a lease
   gets us as router+DNS. Loud and effective; it also makes us the router address,
   so only use it on a network you own. Stop it before you need real internet on
   other devices again.
3. Add inbound firewall rules if the console can't reach us: `python app.py --firewall`
   (elevated), or run once as admin and Windows will have prompted already.

## HTTPS notes

* The cert is generated at first run into `certs\server.crt|key.pem` and cached
  (regenerate with `--regen-cert`). It is a real X.509 v3 cert: RSA-2048,
  SHA-256, `CA:TRUE`, SANs incl. `*.xboxlive.com`, `*.microsoft.com`, `*`,
  `192.168.1.146`, `127.0.0.1`. Extra names: `--san-file hosts.txt`.
* Unpinned clients accept it **only** if you add our CA to their trust store; until
  then you still get the SNI and the failed-handshake line, which is usually the
  interesting part. If you need real acceptance, install `certs\server.crt` on the
  device as a trusted root (or point `--cert/--key` at a real CA-issued pair).
* Old console browsers: `--legacy-tls` allows TLS 1.0/1.1 and legacy ciphers
  (`ALL:@SECLEVEL=0`). Default is TLS ≥ 1.2 + ALPN `http/1.1`.

## Windows specifics worth knowing

* Binding 53/80/443 does **not** need admin on Windows. If a bind fails the startup
  report says which port and why; port 80 can also be held by a `http.sys` URL
  reservation (IIS / WinNAT / Web Deployment Agent).
* Listeners bind **exclusively** (`SO_EXCLUSIVEADDRUSE`), never `SO_REUSEADDR`. With
  `SO_REUSEADDR` on Windows a second process can bind the same UDP port and unicast
  traffic silently goes to whoever bound last — that is how mDNS quietly owns
  `:5353` and how a DNS hijacker ends up answering nobody. Exclusive binding means
  you either own the port or see `WinError 10048` in the startup report.
* That is also why the self-test/alt-run ports avoid 5353 (use 5354): on this
  machine mDNS holds it.

## Tests

```
python test_app_full.py        # 17 tests: real UDP/TCP DNS, TLS handshake+verify,
                               # 302/404/body-capture, /log + /api, DHCP packet build
python test_app.py             # the original dns_reply contract test
python app.py --selftest       # cert + handshake + dns_reply, no privileged ports
python probe_live.py           # starts the real app, probes every port, prints the log
python probe_live.py --alt     # same, on 5354/8081/8443 so nothing needs a free 53
```

## Knobs that matter most

```
--ip 192.168.1.146     the address every A query resolves to (default: LAN IP)
--mode auto|serve|redirect|page|empty
--webroot DIR          files served for matching paths (default: one level up)
--ttl 0                TTL on synthetic answers (0 = clients never cache the lie)
--upstream 8.8.8.8,1.1.1.1 --bypass xboxlive.com   keep some names real
--redirect-template 'https://{host}{path}'         send the client back to the
                                                   requested name instead of our IP
                                                   (placeholders: {ip} {port} {host} {path})
--aaaa nodata|redirect
--no-dns --no-http --no-https --no-logsrv          run only what you need
```
