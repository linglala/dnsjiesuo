#!/usr/bin/env python3
# DNS 解锁集中管理面板 (FastAPI + SQLite)
# 运行: pip install fastapi uvicorn python-multipart
#       ADMIN_PASS=你的强密码 uvicorn panel:app --host 0.0.0.0 --port 8080
import os, time, json, sqlite3, secrets, html
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import uvicorn

DB = os.environ.get("PANEL_DB", "/etc/dnspanel/panel.db")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")  # 上线必须改!
app = FastAPI()

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = db()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS nodes(id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, token TEXT UNIQUE, last_seen REAL DEFAULT 0,
        rx INTEGER DEFAULT 0, tx INTEGER DEFAULT 0, created REAL);
    CREATE TABLE IF NOT EXISTS whitelist(id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE, note TEXT DEFAULT '', created REAL);
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS traffic(node_id INTEGER, day TEXT,
        rx INTEGER DEFAULT 0, tx INTEGER DEFAULT 0,
        PRIMARY KEY(node_id, day));
    ''')
    c.execute("INSERT OR IGNORE INTO settings VALUES('unlock_ip','')")
    c.commit(); c.close()
init()

def get_setting(k, d=''):
    c = db(); r = c.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone(); c.close()
    return r["value"] if r else d

def set_setting(k, v):
    c = db(); c.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v)); c.commit(); c.close()

def logged(req):
    return req.cookies.get("session") == "ok"

DEFAULT_DOMAINS = ['(.*\\.)?(chatgpt|openai|chat|sora|oaistatsig|oaiusercontent|oaistatic|crixet)\\.com\\.?', '(.*\\.)?openaicom\\.imgix\\.net\\.?', '(.*\\.)?arkoselabs\\.com\\.?', '(.*\\.)?(chatgpt|host|turn)\\.livekit\\.cloud\\.?', '(.*\\.)?webpubsub\\.azure\\.com\\.?', '(.*\\.)?gemini\\.google\\.com\\.?', '(.*\\.)?generativelanguage\\.googleapis\\.com\\.?', '(.*\\.)?alkalicore\\.googleapis\\.com\\.?', 'www\\.google\\.com\\.?', 'google\\.com\\.?', '(.*\\.)?ogs\\.google\\.com\\.?']

def get_domains():
    try:
        d = json.loads(get_setting("domains", "[]"))
        return d if d else DEFAULT_DOMAINS
    except Exception:
        return DEFAULT_DOMAINS


# ---------- Agent API ----------
@app.get("/api/v1/config")
def api_config(request: Request):
    token = request.headers.get("X-Node-Token", "")
    c = db()
    if not c.execute("SELECT 1 FROM nodes WHERE token=?", (token,)).fetchone():
        c.close(); raise HTTPException(403, "bad token")
    wl = [r["ip"] for r in c.execute("SELECT ip FROM whitelist").fetchall()]
    c.close()
    return {"unlock_ip": get_setting("unlock_ip"), "whitelist": wl, "domains": get_domains()}

@app.post("/api/v1/report")
async def api_report(request: Request):
    token = request.headers.get("X-Node-Token", "")
    body = await request.json()
    c = db()
    n = c.execute("SELECT * FROM nodes WHERE token=?", (token,)).fetchone()
    if not n:
        name = body.get("name", "node")
        c.execute("INSERT INTO nodes(name,token,created,last_seen) VALUES(?,?,?,?)",
                  (name, token, time.time(), time.time()))
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
    c.commit(); c.close()
    return {"ok": True}

# ---------- Web UI ----------
PAGE = '''<!doctype html><html lang=zh><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>DNS 解锁面板</title><style>
body{font-family:system-ui;max-width:900px;margin:30px auto;padding:0 16px;color:#222}
table{border-collapse:collapse;width:100%;margin:12px 0}td,th{border:1px solid #ddd;padding:6px 10px;font-size:14px}
th{background:#f5f5f5}h2{margin-top:28px}.on{color:green;font-weight:bold}.off{color:#999}
input{padding:6px 8px;margin:4px}button{padding:6px 14px;cursor:pointer}
.card{border:1px solid #ddd;border-radius:8px;padding:14px;margin:12px 0}
a{color:#06c}</style></head><body>
<h1>DNS 解锁面板</h1>
__BODY__
</body></html>'''

def page(body):
    return HTMLResponse(PAGE.replace("__BODY__", body))

LOGIN_HTML = ("<div class=card><h3>登录</h3><form method=post action=/login>"
              "密码: <input type=password name=p><button>进入</button></form></div>")

INDEX_BODY = '''<div class=card><b>解锁 VPS IP:</b> %s
<form method=post action=/set_unlock style="display:inline"> <input name=ip value="%s" placeholder="解锁VPS的IP">
<button>保存</button></form></div>
<div class=card><b>解锁域名 (正则,每行一条):</b>
<form method=post action=/set_domains><textarea name=domains rows=7 style="width:100%%">%s</textarea>
<button>保存</button></form></div>
<h2>DNS 节点 (%d)</h2>
<table><tr><th>ID</th><th>名称</th><th>Token</th><th>状态</th><th>最后心跳</th><th>今日流量</th><th>累计流量</th><th></th></tr>%s</table>
<div class=card><b>添加节点</b><form method=post action=/add_node>
<input name=name placeholder="节点名称,如 dns-东京1" required> <button>生成 Token</button></form></div>
<h2>IP 白名单 (%d)</h2>
<table><tr><th>IP / CIDR</th><th>备注</th><th></th></tr>%s</table>
<div class=card><b>添加白名单 IP</b> <span style="color:#888">(支持 CIDR,如 1.2.3.0/24)</span>
<form method=post action=/add_wl><input name=ip placeholder="1.2.3.4" required>
<input name=note placeholder="备注"> <button>添加</button></form></div>
<p><a href=/logout>退出登录</a></p>'''

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not logged(request):
        return page(LOGIN_HTML)
    c = db()
    nodes = c.execute("SELECT * FROM nodes ORDER BY id").fetchall()
    wl = c.execute("SELECT * FROM whitelist ORDER BY id").fetchall()
    c.close()
    unlock_ip = html.escape(get_setting("unlock_ip"))
    rows = ""
    for n in nodes:
        on = (time.time() - n["last_seen"]) < 120
        day = time.strftime("%Y-%m-%d")
        c2 = db()
        t = c2.execute("SELECT rx,tx FROM traffic WHERE node_id=? AND day=?", (n["id"], day)).fetchone()
        c2.close()
        used = ((n["rx"]-(t["rx"] if t else 0))+(n["tx"]-(t["tx"] if t else 0)))/1e9 if n["last_seen"] else 0
        total = (n["rx"]+n["tx"])/1e9
        status = "在线" if on else "离线"
        cls = "on" if on else "off"
        ls = time.strftime("%H:%M:%S", time.localtime(n["last_seen"])) if n["last_seen"] else "-"
        rows += ("<tr><td>%d</td><td>%s</td><td>%s…</td><td class=%s>%s</td><td>%s</td>"
                 "<td>%.2f GB</td><td>%.2f GB</td><td><a href=/del_node/%d onclick=\"return confirm('删除?')\">删</a></td></tr>"
                 % (n["id"], html.escape(n["name"]), n["token"][:8], cls, status, ls, used, total, n["id"]))
    wlrows = "".join("<tr><td>%s</td><td>%s</td><td><a href=/del_wl/%d onclick=\"return confirm('删除?')\">删</a></td></tr>"
                     % (html.escape(w["ip"]), html.escape(w["note"]), w["id"]) for w in wl)
    body = INDEX_BODY % (
        unlock_ip or '<span style=color:red>未设置!</span>', unlock_ip,
        "\n".join(get_domains()),
        len(nodes), rows or "<tr><td colspan=8>暂无节点</td></tr>",
        len(wl), wlrows or "<tr><td colspan=3>暂无,任何人都能查询,危险!</td></tr>")
    return page(body)

@app.post("/login")
def login(p: str = Form(...)):
    if p == ADMIN_PASS:
        r = RedirectResponse("/", 302); r.set_cookie("session", "ok", max_age=86400*30)
        return r
    return RedirectResponse("/", 302)

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

@app.post("/add_node")
def add_node(request: Request, name: str = Form(...)):
    if logged(request):
        c = db(); c.execute("INSERT INTO nodes(name,token,created) VALUES(?,?,?)",
                            (name.strip(), secrets.token_hex(16), time.time())); c.commit(); c.close()
    return RedirectResponse("/", 302)

@app.get("/del_node/{nid}")
def del_node(request: Request, nid: int):
    if logged(request):
        c = db(); c.execute("DELETE FROM nodes WHERE id=?", (nid,)); c.execute("DELETE FROM traffic WHERE node_id=?", (nid,)); c.commit(); c.close()
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
