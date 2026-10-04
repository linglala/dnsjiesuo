#!/usr/bin/env python3
# DNS 解锁节点 Agent v2: 拉配置/生成 Corefile/上报心跳流量 + 解锁检测
import os, time, json, hashlib, socket, ssl, struct, random, urllib.request

PANEL = os.environ.get("PANEL_URL", "").rstrip("/")
TOKEN = os.environ.get("NODE_TOKEN", "")
NAME  = os.environ.get("NODE_NAME", "node")
COREFILE = os.environ.get("COREFILE", "/etc/coredns/Corefile")
INTERVAL = int(os.environ.get("INTERVAL", "30"))
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "600"))   # 解锁检测间隔(秒)

DOMAINS = ['(.*\\.)?(chatgpt|openai|chat|sora|oaistatsig|oaiusercontent|oaistatic|crixet)\\.com\\.?', '(.*\\.)?openaicom\\.imgix\\.net\\.?', '(.*\\.)?arkoselabs\\.com\\.?', '(.*\\.)?(chatgpt|host|turn)\\.livekit\\.cloud\\.?', '(.*\\.)?webpubsub\\.azure\\.com\\.?', '(.*\\.)?gemini\\.google\\.com\\.?', '(.*\\.)?generativelanguage\\.googleapis\\.com\\.?', '(.*\\.)?alkalicore\\.googleapis\\.com\\.?', '(.*\\.)?(jnn-pa|alkalicore|waa-pa\\.clients6)\\.googleapis\\.com\\.?', '(.*\\.)?apis\\.google\\.com\\.?', 'www\\.google\\.com\\.?', 'google\\.com\\.?', '(.*\\.)?ogs\\.google\\.com\\.?']

# 解锁检测项: 直连解锁IP + SNI, 端到端验证
CHECKS = [
    {"key": "netflix", "domain": "www.netflix.com",      "path": "/title/8011759",    "kind": "code",  "ok": [200]},
    {"key": "youtube", "domain": "www.youtube.com",      "path": "/premium",          "kind": "text",  "need": b"Premium"},
    {"key": "chatgpt", "domain": "chatgpt.com",          "path": "/cdn-cgi/trace",    "kind": "loc"},
    {"key": "gemini",  "domain": "gemini.google.com",    "path": "/",                 "kind": "gemini"},
    {"key": "disney",  "domain": "www.disneyplus.com",   "path": "/",                 "kind": "code",  "ok": [200, 301, 302]},
]
UNSUPPORTED_LOC = {"CN", "HK", "MO", "RU", "IR", "KP", "CU", "VE", "BY", "SY", "SD"}

COREFILE_TPL = ''':53 {
    reload
    acl {
__ALLOW__
        block
    }
    template IN A __ZONES__ {
        answer "{{ .Name }} 60 IN A __IP__"
    }
    forward . 8.8.8.8 1.1.1.1
    cache 300
    errors
    log
}
'''

def api(path, data=None):
    req = urllib.request.Request(PANEL + path, method="GET" if data is None else "POST")
    req.add_header("X-Node-Token", TOKEN)
    if data is not None:
        req.data = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

def read_traffic():
    rx = tx = 0
    with open("/proc/net/dev") as f:
        for line in f.readlines()[2:]:
            iface, rest = line.split(":", 1)
            if iface.strip() == "lo":
                continue
            cols = rest.split()
            rx += int(cols[0]); tx += int(cols[8])
    return rx, tx

def render_corefile(unlock_ip, whitelist, domains):
    zones = " ".join('"%s"' % d for d in domains)
    allow = "\n".join("        allow %s" % ip for ip in whitelist)
    if not allow:
        allow = "        allow 127.0.0.1  # 白名单为空,仅本机,请到面板添加!"
    return (COREFILE_TPL.replace("__ALLOW__", allow)
               .replace("__ZONES__", zones)
               .replace("__IP__", unlock_ip))

# ---------- 解锁检测 ----------
def https_via(domain, ip, path="/", timeout=8):
    # 连接 ip:443 但用 domain 做 SNI/Host, 模拟用户经解锁后的访问
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((ip, 443), timeout=timeout)
    try:
        ss = ctx.wrap_socket(sock, server_hostname=domain)
        ss.settimeout(timeout)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n") % (path, domain)
        ss.sendall(req.encode())
        data = b""
        while True:
            try:
                chunk = ss.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 300000:
                break
        head, _, body = data.partition(b"\r\n\r\n")
        parts = head.split(b" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        return status, head, body
    finally:
        try: sock.close()
        except Exception: pass

def dns_query_a(server, name, timeout=4):
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(q, (server, 53))
        data, _ = sock.recvfrom(2048)
    finally:
        sock.close()
    if struct.unpack(">H", data[:2])[0] != tid:
        return []
    an = struct.unpack(">H", data[6:8])[0]
    i = 12
    while data[i] != 0:
        i += data[i] + 1
    i += 5
    ips = []
    for _ in range(an):
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while data[i] != 0:
                i += data[i] + 1
            i += 1
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[i:i+10])
        i += 10
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in data[i:i+4]))
        i += rdlen
    return ips

def run_checks(unlock_ip):
    out = {}
    # DNS 规则自检: 本机 CoreDNS 是否返回解锁IP
    try:
        ips = dns_query_a("127.0.0.1", "chatgpt.com")
        hit = unlock_ip in ips
        out["dns"] = {"ok": hit, "detail": ("本机DNS返回: " + ",".join(ips)) if ips else "无解析结果"}
    except Exception as e:
        out["dns"] = {"ok": False, "detail": "DNS查询失败: %s" % e}
    for c in CHECKS:
        try:
            status, head, body = https_via(c["domain"], unlock_ip, c["path"])
            if c["kind"] == "code":
                ok = status in c["ok"]
                out[c["key"]] = {"ok": ok, "detail": "HTTP %d" % status}
            elif c["kind"] == "text":
                ok = status == 200 and c["need"] in body
                out[c["key"]] = {"ok": ok, "detail": "HTTP %d" % status}
            elif c["kind"] == "loc":
                loc = ""
                for line in body.decode("utf-8", "ignore").splitlines():
                    if line.startswith("loc="):
                        loc = line[4:].strip().upper()
                ok = bool(loc) and loc not in UNSUPPORTED_LOC
                out[c["key"]] = {"ok": ok, "detail": "出口区域: %s" % (loc or "未知")}
            elif c["kind"] == "gemini":
                blocked = (status in (301, 302) and b"unavailable" in head) or status == 403
                out[c["key"]] = {"ok": not blocked, "detail": "HTTP %d" % status}
        except Exception as e:
            out[c["key"]] = {"ok": False, "detail": "检测异常: %s" % e}
    return out

last_hash = None
next_check = 0.0
while True:
    try:
        cfg = api("/api/v1/config")
        unlock_ip = cfg.get("unlock_ip", "").strip()
        h = hashlib.md5(json.dumps(cfg, sort_keys=True).encode()).hexdigest()
        if h != last_hash:
            if unlock_ip:
                os.makedirs(os.path.dirname(COREFILE), exist_ok=True)
                tmp = COREFILE + ".tmp"
                with open(tmp, "w") as f:
                    f.write(render_corefile(unlock_ip, cfg.get("whitelist", []), cfg.get("domains") or DOMAINS))
                os.replace(tmp, COREFILE)
                last_hash = h
                print("[%s] Corefile updated (unlock_ip=%s, wl=%d)" % (time.strftime("%H:%M:%S"), unlock_ip, len(cfg.get("whitelist", []))), flush=True)
            else:
                print("[%s] unlock_ip not set on panel, skip" % time.strftime("%H:%M:%S"), flush=True)
        rx, tx = read_traffic()
        payload = {"name": NAME, "rx": rx, "tx": tx}
        if unlock_ip and time.time() >= next_check:
            print("[%s] running unlock checks..." % time.strftime("%H:%M:%S"), flush=True)
            payload["checks"] = run_checks(unlock_ip)
            next_check = time.time() + CHECK_INTERVAL
        api("/api/v1/report", payload)
    except Exception as e:
        print("[%s] error: %s" % (time.strftime("%H:%M:%S"), e), flush=True)
    time.sleep(INTERVAL)
