"""Raw TLS ClientHello dumper on :443 — logs SNI, version, ciphers, ALPN, groups.
Runs for N seconds then exits. Pairs with `app.py --no-https` so DNS/HTTP stay up."""
import socket, struct, sys, time, threading, datetime

LOGPATH = r"D:\XBOX one hacking\redirect\lan_dns_web\ch_dump.log"
LOG = open(LOGPATH, "a", buffering=1)

def log(msg):
    line = f"[{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}"
    print(line, flush=True)
    LOG.write(line + "\n")

CIPHER = {
 0x1301:"TLS_AES_128_GCM_SHA256",0x1302:"TLS_AES_256_GCM_SHA384",0x1303:"TLS_CHACHA20_POLY1305_SHA256",
 0xc02b:"ECDHE_ECDSA_AES128_GCM",0xc02c:"ECDHE_ECDSA_AES256_GCM",0xc02f:"ECDHE_RSA_AES128_GCM",0xc030:"ECDHE_RSA_AES256_GCM",
 0xc009:"ECDHE_ECDSA_AES128_CBC",0xc00a:"ECDHE_ECDSA_AES256_CBC",0xc013:"ECDHE_RSA_AES128_CBC",0xc014:"ECDHE_RSA_AES256_CBC",
 0xcca8:"ECDHE_RSA_CHACHA20",0xcca9:"ECDHE_ECDSA_CHACHA20",
 0x009c:"RSA_AES128_GCM",0x009d:"RSA_AES256_GCM",
 0x002f:"RSA_AES128_CBC_SHA",0x0035:"RSA_AES256_CBC_SHA",
 0xc023:"ECDHE_ECDSA_AES128_CBC_SHA256",0xc024:"ECDHE_ECDSA_AES256_CBC_SHA384",
 0xc027:"ECDHE_RSA_AES128_CBC_SHA256",0xc028:"ECDHE_RSA_AES256_CBC_SHA384",
 0x000a:"RSA_AES256_CBC_SHA",0x0005:"RSA_RC4_128_SHA",0x0004:"RSA_RC4_128_MD5",
 0x0067:"DHE_RSA_AES128_CBC_SHA",0x006b:"DHE_RSA_AES256_CBC_SHA",
}
VER={0x0300:"SSL3",0x0301:"TLS1.0",0x0302:"TLS1.1",0x0303:"TLS1.2",0x0304:"TLS1.3"}
GROUP={0x001d:"x25519",0x001e:"x448",0x0017:"secp256r1",0x0018:"secp384r1",0x0019:"secp521r1",
 0x0100:"ffdhe2048",0x0101:"ffdhe3072",0x0102:"ffdhe4096",0x0103:"ffdhe6144",0x0104:"ffdhe8192",
 0x0016:"secp256k1"}
SIG={0x0403:"ecdsa_secp256r1_sha256",0x0503:"ecdsa_secp384r1_sha384",0x0603:"ecdsa_secp521r1_sha512",
 0x0401:"rsa_pkcs1_sha256",0x0501:"rsa_pkcs1_sha384",0x0601:"rsa_pkcs1_sha512",
 0x0804:"rsa_pss_rsae_sha256",0x0805:"rsa_pss_rsae_sha384",0x0806:"rsa_pss_rsae_sha512",
 0x0201:"rsa_pkcs1_sha1",0x0203:"ecdsa_sha1"}

def parse_hello(data):
    if len(data) < 5 or data[0] != 0x16: return None
    rec_len = struct.unpack(">H", data[3:5])[0]
    if len(data) < 5 + rec_len: return None
    hs = data[5:5+rec_len]
    if hs[0] != 0x01: return None
    p = 4
    ver = struct.unpack(">H", hs[p:p+2])[0]; p += 2
    p += 32
    sid_len = hs[p]; p += 1 + sid_len
    cs_len = struct.unpack(">H", hs[p:p+2])[0]; p += 2
    cs = [struct.unpack(">H", hs[p+i:p+i+2])[0] for i in range(0, cs_len, 2)]
    p += cs_len
    cm_len = hs[p]; p += 1 + cm_len
    exts = {}
    if p + 2 <= len(hs):
        ext_total = struct.unpack(">H", hs[p:p+2])[0]; p += 2
        end = p + ext_total
        while p + 4 <= end:
            et = struct.unpack(">H", hs[p:p+2])[0]
            el = struct.unpack(">H", hs[p+2:p+4])[0]; p += 4
            exts[et] = hs[p:p+el]; p += el
    sni=None; alpn=[]; supver=[]; groups=[]; sigs=[]
    if 0 in exts:
        ed = exts[0]; nl = struct.unpack(">H", ed[3:5])[0]; sni = ed[5:5+nl].decode('ascii','replace')
    if 0x10 in exts:
        ed = exts[0x10]; ln = struct.unpack(">H", ed[0:2])[0]; i = 2
        while i < 2+ln:
            nl = ed[i]; alpn.append(ed[i+1:i+1+nl].decode('ascii','replace')); i += 1+nl
    if 0x2b in exts:
        ed = exts[0x2b]; ln = ed[0]; i = 1
        while i < 1+ln:
            supver.append(struct.unpack(">H", ed[i:i+2])[0]); i += 2
    if 0x0a in exts:
        ed = exts[0x0a]; ln = struct.unpack(">H", ed[0:2])[0]; i = 2
        while i < 2+ln:
            groups.append(struct.unpack(">H", ed[i:i+2])[0]); i += 2
    if 0x0d in exts:
        ed = exts[0x0d]; ln = struct.unpack(">H", ed[0:2])[0]; i = 2
        while i < 2+ln:
            sigs.append(struct.unpack(">H", ed[i:i+2])[0]); i += 2
    return dict(ver=ver, ciphers=cs, sni=sni, alpn=alpn, supver=supver,
                groups=groups, sigs=sigs, ext_keys=sorted(exts.keys()), raw=data)

def handle(conn, addr):
    try:
        conn.settimeout(6)
        data = b""
        while len(data) < 5:
            chunk = conn.recv(4096)
            if not chunk: break
            data += chunk
        if len(data) < 5:
            log(f"{addr[0]}:{addr[1]} <no hello> ({len(data)}B)"); return
        rec_len = struct.unpack(">H", data[3:5])[0]
        while len(data) < 5 + rec_len:
            chunk = conn.recv(4096)
            if not chunk: break
            data += chunk
        info = parse_hello(data)
        if not info:
            log(f"{addr[0]}:{addr[1]} unparsed {len(data)}B head={data[:20].hex()}"); return
        sv = ",".join(VER.get(v, hex(v)) for v in info['supver']) or "-"
        log(f"{addr[0]}:{addr[1]}  SNI={info['sni']}  ch_ver={VER.get(info['ver'],hex(info['ver']))}  supported_versions=[{sv}]  ALPN=[{','.join(info['alpn']) or '-'}]")
        log(f"      ciphers({len(info['ciphers'])}): {' '.join(CIPHER.get(c, hex(c)) for c in info['ciphers'])}")
        log(f"      groups: {[GROUP.get(g,hex(g)) for g in info['groups']]}")
        log(f"      sig_algs: {[SIG.get(s,hex(s)) for s in info['sigs']]}")
        log(f"      ext_types: {[hex(k) for k in info['ext_keys']]}")
        log(f"      raw({len(info['raw'])}B): {info['raw'][:160].hex()}")
        LOG.flush()
    except Exception as e:
        log(f"{addr[0]}:{addr[1]} err {type(e).__name__}: {e}")
    finally:
        try: conn.close()
        except Exception: pass

def main():
    dur = float(sys.argv[1]) if len(sys.argv) > 1 else 180.0
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    except Exception:
        pass
    s.bind(("0.0.0.0", 443))
    s.listen(64)
    s.settimeout(2)
    log(f"=== ClientHello dumper on :443 for {dur:.0f}s ===")
    end = time.time() + dur
    n = 0
    while time.time() < end:
        try:
            conn, addr = s.accept()
        except socket.timeout:
            continue
        n += 1
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    log(f"=== dumper done ({n} connections) ===")
    s.close()

if __name__ == "__main__":
    main()
