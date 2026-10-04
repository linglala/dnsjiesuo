#!/usr/bin/env python3
# DNS 解锁集中管理面板 v3 (FastAPI + SQLite, 单文件)
# v3: 修改密码 + 节点解锁检测展示
import os, time, json, sqlite3, secrets, html
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import uvicorn

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("PANEL_DB", os.path.join(BASE, "panel.db"))
app = FastAPI()

DEFAULT_DOMAINS = ['chatgpt.com', 'openai.com', 'chat.com', 'sora.com', 'oaistatsig.com', 'oaiusercontent.com', 'oaistatic.com', 'crixet.com', 'openaicom.imgix.net', 'arkoselabs.com', 'chatgpt.livekit.cloud', 'host.livekit.cloud', 'turn.livekit.cloud', 'webpubsub.azure.com', 'gemini.google.com', 'generativelanguage.googleapis.com', 'alkalicore.googleapis.com', 'jnn-pa.googleapis.com', 'waa-pa.clients6.google.com', 'apis.google.com', 'www.google.com', 'ogs.google.com', 'google.com']

SERVICES = [("dns", "DNS规则"), ("netflix", "奈飞"), ("youtube", "YouTube"), ("chatgpt", "ChatGPT"), ("gemini", "Gemini"), ("disney", "Disney+")]

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init():
    os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS nodes(id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, token TEXT UNIQUE, last_seen REAL DEFAULT 0,
        rx INTEGER DEFAULT 0, tx INTEGER DEFAULT 0, created REAL);
    CREATE TABLE IF NOT EXISTS whitelist(id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE, note TEXT DEFAULT '', created REAL);
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS traffic(node_id INTEGER, day TEXT,
        rx INTEGER DEFAULT 0, tx INTEGER DEFAULT 0,
        PRIMARY KEY(node_id, day));
    CREATE TABLE IF NOT EXISTS node_checks(node_id INTEGER PRIMARY KEY,
        data TEXT, ts REAL DEFAULT 0);
    """)
    for col in ("ips", "domains"):
        try:
            c.execute("ALTER TABLE nodes ADD COLUMN %s TEXT DEFAULT ''" % col)
        except Exception:
            pass
    c.commit(); c.close()
    if not get_setting("admin_pass"):
        env = os.environ.get("ADMIN_PASS", "changeme").strip()
        if env and env != "changeme":
            set_setting("admin_pass", env)
        else:
            p = secrets.token_urlsafe(9)
            try:
                fp = os.path.join(os.path.dirname(DB), "initial_password.txt")
                with open(fp, "w") as f: f.write(p + "\n")
                os.chmod(fp, 0o600)
            except Exception: pass
            set_setting("admin_pass", p)
            print("[panel] 初始密码已生成, 见 initial_password.txt 或本日志:", p, flush=True)

def get_setting(k, d=''):
    c = db(); r = c.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone(); c.close()
    return r["value"] if r else d

def set_setting(k, v):
    c = db(); c.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v)); c.commit(); c.close()

def get_domains():
    try:
        d = json.loads(get_setting("domains", "[]"))
        return d if d else list(DEFAULT_DOMAINS)
    except Exception:
        return list(DEFAULT_DOMAINS)

def logged(req):
    return req.cookies.get("session") == "ok"

def node_by_token(token):
    c = db()
    n = c.execute("SELECT * FROM nodes WHERE token=?", (token,)).fetchone()
    c.close()
    return n

_fails = {"count": 0, "until": 0.0}
init()

# ---------- agent api ----------
@app.get("/api/v1/config")
def api_config(request: Request):
    n = node_by_token(request.headers.get("X-Node-Token", ""))
    if not n: raise HTTPException(403, "bad token")
    c = db()
    wl = [r["ip"] for r in c.execute("SELECT ip FROM whitelist").fetchall()]
    c.close()
    nips = [i for i in (n["ips"] or "").split(",") if i and i not in ("127.0.0.1", "::1")]
    answer_ip = nips[0] if nips else get_setting("unlock_ip")
    domains = [l.split()[0] for l in get_domains() if l.split()]
    return {"answer_ip": answer_ip, "unlock_ip": answer_ip, "whitelist": wl, "domains": domains}

@app.post("/api/v1/report")
async def api_report(request: Request):
    token = request.headers.get("X-Node-Token", "")
    body = await request.json()
    c = db()
    n = c.execute("SELECT * FROM nodes WHERE token=?", (token,)).fetchone()
    if not n:
        c.execute("INSERT INTO nodes(name,token,created,last_seen) VALUES(?,?,?,?)",
                  (body.get("name", "node"), token, time.time(), time.time()))
        nid = c.execute("SELECT last_insert_rowid() AS i").fetchone()["i"]
    else:
        nid = n["id"]
        c.execute("UPDATE nodes SET name=COALESCE(NULLIF(?,''),name), last_seen=? WHERE id=?",
                  (body.get("name",""), time.time(), nid))
    rx, tx = int(body.get("rx", 0)), int(body.get("tx", 0))
    c.execute("UPDATE nodes SET rx=?, tx=? WHERE id=?", (rx, tx, nid))
    day = time.strftime("%Y-%m-%d")
    row = c.execute("SELECT * FROM traffic WHERE node_id=? AND day=?", (nid, day)).fetchone()
    if row:
        c.execute("UPDATE traffic SET rx=MAX(rx,?), tx=MAX(tx,?) WHERE node_id=? AND day=?", (rx, tx, nid, day))
    else:
        c.execute("INSERT INTO traffic VALUES(?,?,?,?)", (nid, day, rx, tx))
    if "ips" in body:
        c.execute("UPDATE nodes SET ips=? WHERE id=?", (",".join(body["ips"]), nid))
    if "checks" in body:
        c.execute("INSERT INTO node_checks VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET data=excluded.data, ts=excluded.ts",
                  (nid, json.dumps(body["checks"]), time.time()))
    c.commit(); c.close()
    return {"ok": True}

# ---------- ui ----------
PAGE = """<!doctype html><html lang=zh><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta http-equiv=refresh content="60">
<title>DNS 解锁面板</title><style>
:root{--bg:#f4f6fb;--card:#fff;--line:#e5e9f2;--text:#1f2733;--sub:#8a94a6;--pri:#4f46e5;--pri2:#4338ca;--ok:#16a34a;--bad:#dc2626;--warn:#d97706}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--text);font-size:14px}
.wrap{max-width:1040px;margin:0 auto;padding:24px 16px 60px}
header{display:flex;justify-content:space-between;align-items:center;padding:14px 0 22px}
h1{font-size:20px;display:flex;align-items:center;gap:8px}
h1 .dot{width:9px;height:9px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px rgba(22,163,74,.15)}
a{color:var(--pri);text-decoration:none}a:hover{text-decoration:underline}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px;box-shadow:0 1px 2px rgba(16,24,40,.04)}
.card h2{font-size:15px;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.card h2 .n{font-size:12px;color:var(--sub);font-weight:normal}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--sub);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:#fafbff}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600}
.badge.on{color:var(--ok);background:#e8f7ee}
.badge.off{color:var(--sub);background:#eef1f6}
.svc{display:inline-block;padding:2px 9px;border-radius:6px;font-size:12px;font-weight:600;margin:1px 2px}
.svc.ok{color:var(--ok);background:#e8f7ee}
.svc.bad{color:var(--bad);background:#fdecec}
.svc.unk{color:var(--sub);background:#eef1f6}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--sub)}
input,textarea{font:inherit;padding:8px 11px;border:1px solid var(--line);border-radius:8px;background:#fbfcfe;outline:none;transition:.15s}
input:focus,textarea:focus{border-color:var(--pri);background:#fff;box-shadow:0 0 0 3px rgba(79,70,229,.1)}
button{font:inherit;font-weight:600;padding:8px 16px;border:none;border-radius:8px;background:var(--pri);color:#fff;cursor:pointer;transition:.15s}
button:hover{background:var(--pri2)}
button.ghost{background:#eef0f6;color:var(--text)}
button.ghost:hover{background:#e3e6ef}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.muted{color:var(--sub);font-size:12px}
.warn{color:var(--warn);font-size:12px}
textarea{width:100%;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.7;resize:vertical}
footer{text-align:center;color:var(--sub);font-size:12px;margin-top:24px}
.copybtn{padding:4px 12px;font-size:12px;font-weight:600;background:#eef0f6;color:var(--text);border:1px solid var(--line)}
.copybtn:hover{background:#e3e6ef}
.copybtn.done{background:#e8f7ee;color:var(--ok);border-color:#bbe7cb}
.login-box{max-width:360px;margin:10vh auto 0}
.big-ip{font-family:ui-monospace,Menlo,monospace;font-weight:700;font-size:16px}
.msg{padding:9px 13px;border-radius:8px;font-size:13px;margin-bottom:14px}
.msg.okmsg{color:var(--ok);background:#e8f7ee}
.msg.errmsg{color:var(--bad);background:#fdecec}
</style></head><body><div class=wrap>
__BODY__
<footer>DNS 解锁面板 v3 &middot; 每 60 秒自动刷新</footer>
</div>
<script>
function copyCmd(btn){
  var t = btn.getAttribute('data-cmd');
  function ok(){ var o=btn.textContent; btn.textContent='✓ 已复制'; btn.classList.add('done');
    setTimeout(function(){ btn.textContent=o; btn.classList.remove('done'); },1500); }
  function fb(){ var ta=document.createElement('textarea'); ta.value=t; ta.style.position='fixed'; ta.style.opacity='0';
    document.body.appendChild(ta); ta.select();
    try{ document.execCommand('copy'); ok(); }catch(e){ prompt('复制失败,请手动复制:', t); }
    document.body.removeChild(ta); }
  if (navigator.clipboard && window.isSecureContext !== false) {
    navigator.clipboard.writeText(t).then(ok, fb);
  } else { fb(); }
}
</script>
</body></html>"""

def page(b): return HTMLResponse(PAGE.replace("__BODY__", b))

LOGIN_HTML = """<div class="card login-box"><h2>🔐 登录</h2>
<form method=post action=/login class=row style="flex-direction:column;align-items:stretch">
<input type=password name=p placeholder="管理密码" autofocus>
<button>登录</button></form>
<p class=muted style="margin-top:12px">初始密码见服务器上的 initial_password.txt</p></div>"""

INDEX_HEAD = """<header><h1><span class=dot></span>DNS 解锁面板</h1><a href=/logout>退出登录</a></header>
__MSG__
<div class=card><h2>解锁检测 <span class=n>各节点通过解锁 IP 实测,每 10 分钟更新</span></h2>
<table><thead><tr><th>节点</th><th>DNS规则</th><th>奈飞</th><th>YouTube</th><th>ChatGPT</th><th>Gemini</th><th>Disney+</th><th>检测时间</th></tr></thead>
<tbody>__CHECKS__</tbody></table></div>

<div class=card><h2>DNS 节点 <span class=n>共 __NN__ 台</span></h2>
<table><thead><tr><th>ID</th><th>名称</th><th>Token</th><th>本机IP</th><th>负责域名</th><th>状态</th><th>最后心跳</th><th>今日流量</th><th>累计流量</th><th></th></tr></thead>
<tbody>__NODES__</tbody></table>
<div class=row style="margin-top:12px"><b>添加节点</b>
<form method=post action=/add_node class=row><input name=name placeholder="节点名称,如 dns-东京1" required><button>生成 Token</button></form></div></div>

<div class=card><h2>IP 白名单 <span class=n>支持 CIDR,如 1.2.3.0/24</span></h2>
<table><thead><tr><th>IP / CIDR</th><th>备注</th><th></th></tr></thead><tbody>__WL__</tbody></table>
<div class=row style="margin-top:12px"><b>添加白名单</b>
<form method=post action=/add_wl class=row><input name=ip placeholder="1.2.3.4" required><input name=note placeholder="备注(可选)"><button>添加</button></form>
__WL_WARN__</div></div>

<div class=card><h2>解锁域名 <span class=n>所有节点共用此名单并各自回答自己的公网IP; 分流由 V2bX dns.json 决定; 每行一个域名,自动含子域</span></h2>
<form method=post action=/set_domains><textarea name=domains rows=11>__DOMAINS__</textarea>
<div class=row style="margin-top:10px"><button>保存域名</button>
<button class=ghost form=resetdoms>恢复默认</button></form>
<form id=resetdoms method=post action=/reset_domains></form></div></div>

<details style="margin-bottom:16px"><summary style="cursor:pointer;color:var(--sub);font-size:13px;padding:8px 0">🔧 备用解锁 IP(节点未上报公网IP时的回退值,一般不用) ▾</summary>
<div class=card><h2>备用解锁 IP</h2>
<div class=row><span class="big-ip">__UNLOCK_SHOW__</span>
<form method=post action=/set_unlock class=row><input name=ip value="__UNLOCK_VAL__" placeholder="解锁 VPS 的 IP" style="width:220px"><button>保存</button></form></div></div>
</details>

<div class=card><h2>修改密码</h2>
<form method=post action=/change_password class=row>
<input type=password name=old placeholder="当前密码" required>
<input type=password name=new1 placeholder="新密码(至少8位)" required>
<input type=password name=new2 placeholder="确认新密码" required>
<button>修改</button></form></div>"""

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not logged(request): return page(LOGIN_HTML)
    host = request.headers.get("host", "面板IP:8080")
    if host.startswith("localhost") or host.startswith("127."):
        host = "面板IP:8080"
    c = db()
    nodes = c.execute("SELECT * FROM nodes ORDER BY id").fetchall()
    wl = c.execute("SELECT * FROM whitelist ORDER BY id").fetchall()
    checks = {r["node_id"]: (json.loads(r["data"]), r["ts"]) for r in c.execute("SELECT * FROM node_checks").fetchall()}
    c.close()
    unlock = get_setting("unlock_ip")
    # 检测表
    ck_rows = ""
    for n in nodes:
        data, ts = checks.get(n["id"], ({}, 0))
        tds = ""
        for key, label in SERVICES:
            item = data.get(key)
            if item is None:
                tds += "<td><span class='svc unk'>未测</span></td>"
            elif item.get("ok") is None:
                tds += "<td><span class='svc unk' title='%s'>其他节点</span></td>" % html.escape(item.get("detail", ""))
            elif item.get("ok"):
                detail = item.get("detail", "")
                tds += "<td><span class='svc ok' title='%s'>%s ✓</span></td>" % (html.escape(detail), label)
            else:
                detail = item.get("detail", "")
                tds += "<td><span class='svc bad' title='%s'>%s ✗</span></td>" % (html.escape(detail), label)
        ck_rows += "<tr><td><b>%s</b></td>%s<td class=mono>%s</td></tr>" % (
            html.escape(n["name"]), tds,
            time.strftime("%H:%M", time.localtime(ts)) if ts else "-")
    if not nodes:
        ck_rows = "<tr><td colspan=8 class=muted>暂无节点</td></tr>"
    # 节点表
    rows = ""
    for n in nodes:
        on = (time.time() - n["last_seen"]) < 120
        day = time.strftime("%Y-%m-%d")
        c2 = db()
        t = c2.execute("SELECT rx,tx FROM traffic WHERE node_id=? AND day=?", (n["id"], day)).fetchone()
        c2.close()
        used = ((n["rx"]-(t["rx"] if t else 0))+(n["tx"]-(t["tx"] if t else 0)))/1e9 if n["last_seen"] else 0
        total = (n["rx"]+n["tx"])/1e9
        badge = "<span class=badge on>在线</span>" if on else "<span class=badge off>离线</span>"
        ls = time.strftime("%m-%d %H:%M:%S", time.localtime(n["last_seen"])) if n["last_seen"] else "-"
        panel_addr = host if host.startswith("http") else "http://" + host
        install_cmd = "curl -fsSL https://raw.githubusercontent.com/linglala/dnsjiesuo/main/install.sh | bash -s -- %s %s %s" % (
            n["token"], html.escape(panel_addr), html.escape(n["name"]))
        nips = set((n["ips"] or "").split(",")) if n["ips"] else set()
        mine = len(get_domains())
        ipshow = "<br>".join(html.escape(i) for i in sorted(nips)) if nips else "<span class=warn>未上报</span>"
        rows += ("<tr><td>%d</td><td>%s</td><td class=mono>%s…</td><td class=mono>%s</td><td>%d 条</td><td>%s</td><td class=mono>%s</td>"
                 "<td>%.2f GB</td><td>%.2f GB</td>"
                 "<td><a href=/del_node/%d onclick=\"return confirm('删除该节点?')\">删除</a></td></tr>"
                 "<tr><td></td><td colspan=9><button type=button class=copybtn data-cmd=\"%s\" onclick=copyCmd(this)>📋 复制一键安装命令</button> <span class=muted>所有节点共用上方解锁域名名单,各自回答自己的公网IP</span></td></tr>"
                 % (n["id"], html.escape(n["name"]), n["token"][:8], ipshow, mine, badge, ls, used, total, n["id"], html.escape(install_cmd, quote=True)))
    wlrows = "".join("<tr><td class=mono>%s</td><td>%s</td><td><a href=/del_wl/%d onclick=\"return confirm('删除?')\">删除</a></td></tr>"
                     % (html.escape(w["ip"]), html.escape(w["note"] or "-"), w["id"]) for w in wl)
    wlwarn = ""
    if not wl:
        wlwarn = "<p class=warn>⚠ 白名单为空时所有 DNS 节点仅允许本机查询,外部节点无法使用</p>"
    msg = ""
    q = request.query_params
    if q.get("msg") == "pwok":
        msg = "<div class='msg okmsg'>✓ 密码修改成功</div>"
    elif q.get("msg") == "pwbad":
        msg = "<div class='msg errmsg'>✗ 密码修改失败:当前密码错误或两次输入不一致(至少8位)</div>"
    body = (INDEX_HEAD
            .replace("__MSG__", msg)
            .replace("__CHECKS__", ck_rows)
            .replace("__UNLOCK_SHOW__", html.escape(unlock) if unlock else "<span class=warn>未设置! 请填写</span>")
            .replace("__UNLOCK_VAL__", html.escape(unlock))
            .replace("__DOMAINS__", html.escape("\n".join(get_domains())))
            .replace("__NN__", str(len(nodes)))
            .replace("__NODES__", rows or "<tr><td colspan=8 class=muted>暂无节点,点击下方添加</td></tr>")
            .replace("__WL__", wlrows or "<tr><td colspan=3 class=muted>暂无记录</td></tr>")
            .replace("__WL_WARN__", wlwarn))
    return page(body)

@app.post("/login")
def login(p: str = Form(...)):
    now = time.time()
    if now < _fails["until"]:
        return RedirectResponse("/", 302)
    if p == get_setting("admin_pass"):
        _fails.update(count=0, until=0.0)
        r = RedirectResponse("/", 302)
        r.set_cookie("session", "ok", max_age=86400*30, httponly=True, samesite="lax")
        return r
    _fails["count"] += 1
    if _fails["count"] >= 5:
        _fails["until"] = now + 60
        _fails["count"] = 0
    return RedirectResponse("/", 302)

@app.post("/change_password")
def change_password(request: Request, old: str = Form(...), new1: str = Form(...), new2: str = Form(...)):
    if logged(request) and old == get_setting("admin_pass") and new1 == new2 and len(new1) >= 8:
        set_setting("admin_pass", new1)
        return RedirectResponse("/?msg=pwok", 302)
    return RedirectResponse("/?msg=pwbad", 302)

@app.get("/logout")
def logout():
    r = RedirectResponse("/", 302); r.delete_cookie("session"); return r

@app.post("/set_unlock")
def set_unlock(request: Request, ip: str = Form(...)):
    if logged(request): set_setting("unlock_ip", ip.strip())
    return RedirectResponse("/", 302)

@app.post("/set_domains")
def set_domains(request: Request, domains: str = Form(...)):
    if logged(request):
        lines = [l.strip() for l in domains.replace("\r", "").split("\n") if l.strip()]
        set_setting("domains", json.dumps(lines))
    return RedirectResponse("/", 302)

@app.post("/reset_domains")
def reset_domains(request: Request):
    if logged(request):
        c = db(); c.execute("DELETE FROM settings WHERE key='domains'"); c.commit(); c.close()
    return RedirectResponse("/", 302)

@app.post("/set_node_domains/{nid}")
def set_node_domains(request: Request, nid: int, domains: str = Form(...)):
    if logged(request):
        lines = [l.strip() for l in domains.replace("\r", "").split("\n") if l.strip()]
        c = db(); c.execute("UPDATE nodes SET domains=? WHERE id=?", ("\n".join(lines), nid)); c.commit(); c.close()
    return RedirectResponse("/", 302)

@app.post("/add_node")
def add_node(request: Request, name: str = Form(...)):
    if logged(request):
        c = db(); c.execute("INSERT INTO nodes(name,token,created) VALUES(?,?,?)",
                            (name.strip(), secrets.token_hex(16), time.time())); c.commit(); c.close()
    return RedirectResponse("/", 302)

@app.get("/del_node/{nid}")
def del_node(request: Request, nid: int):
    if logged(request):
        c = db(); c.execute("DELETE FROM nodes WHERE id=?", (nid,)); c.execute("DELETE FROM traffic WHERE node_id=?", (nid,)); c.execute("DELETE FROM node_checks WHERE node_id=?", (nid,)); c.commit(); c.close()
    return RedirectResponse("/", 302)

@app.post("/add_wl")
def add_wl(request: Request, ip: str = Form(...), note: str = Form("")):
    if logged(request):
        c = db()
        c.execute("INSERT OR IGNORE INTO whitelist(ip,note,created) VALUES(?,?,?)", (ip.strip(), note.strip(), time.time()))
        c.commit(); c.close()
    return RedirectResponse("/", 302)

@app.get("/del_wl/{wid}")
def del_wl(request: Request, wid: int):
    if logged(request):
        c = db(); c.execute("DELETE FROM whitelist WHERE id=?", (wid,)); c.commit(); c.close()
    return RedirectResponse("/", 302)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
