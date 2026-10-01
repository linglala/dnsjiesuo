#!/usr/bin/env python3
# DNS 解锁节点 Agent: 拉取配置 -> 生成 Corefile -> CoreDNS 热重载; 上报心跳+流量
# 配置环境变量: PANEL_URL / NODE_TOKEN / NODE_NAME
import os, time, json, hashlib, urllib.request

PANEL = os.environ.get("PANEL_URL", "").rstrip("/")      # 如 http://面板IP:8080
TOKEN = os.environ.get("NODE_TOKEN", "")                 # 面板添加节点后生成的 Token
NAME  = os.environ.get("NODE_NAME", "node")
COREFILE = os.environ.get("COREFILE", "/etc/coredns/Corefile")
INTERVAL = int(os.environ.get("INTERVAL", "30"))

# ChatGPT 解锁域名 (正则,匹配主域+所有子域)
DOMAINS = ['(.*\\.)?(chatgpt|openai|chat|sora|oaistatsig|oaiusercontent|oaistatic|crixet)\\.com\\.?', '(.*\\.)?openaicom\\.imgix\\.net\\.?', '(.*\\.)?arkoselabs\\.com\\.?', '(.*\\.)?(chatgpt|host|turn)\\.livekit\\.cloud\\.?', '(.*\\.)?webpubsub\\.azure\\.com\\.?', '(.*\\.)?gemini\\.google\\.com\\.?', '(.*\\.)?generativelanguage\\.googleapis\\.com\\.?', '(.*\\.)?alkalicore\\.googleapis\\.com\\.?', '(.*\\.)?(jnn-pa|alkalicore|waa-pa\\.clients6)\\.googleapis\\.com\\.?', '(.*\\.)?apis\\.google\\.com\\.?', 'www\\.google\\.com\\.?', 'google\\.com\\.?', '(.*\\.)?ogs\\.google\\.com\\.?']

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

last_hash = None
while True:
    try:
        cfg = api("/api/v1/config")
        h = hashlib.md5(json.dumps(cfg, sort_keys=True).encode()).hexdigest()
        if h != last_hash:
            ip = cfg.get("unlock_ip", "").strip()
            if ip:
                os.makedirs(os.path.dirname(COREFILE), exist_ok=True)
                tmp = COREFILE + ".tmp"
                with open(tmp, "w") as f:
                    f.write(render_corefile(ip, cfg.get("whitelist", []), cfg.get("domains") or DOMAINS))
                os.replace(tmp, COREFILE)
                last_hash = h
                print("[%s] Corefile updated (unlock_ip=%s, wl=%d)" % (time.strftime("%H:%M:%S"), ip, len(cfg.get("whitelist", []))), flush=True)
            else:
                print("[%s] unlock_ip not set on panel, skip" % time.strftime("%H:%M:%S"), flush=True)
        rx, tx = read_traffic()
        api("/api/v1/report", {"name": NAME, "rx": rx, "tx": tx})
    except Exception as e:
        print("[%s] error: %s" % (time.strftime("%H:%M:%S"), e), flush=True)
    time.sleep(INTERVAL)
