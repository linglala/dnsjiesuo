# DNS 解锁集中管理面板

自建多节点 DNS 解锁系统：CoreDNS 负责解析（IP 白名单 + 域名指向解锁 VPS），Agent 负责拉取配置和上报监控，面板负责统一管理。

## 功能

- **IP 白名单**：只有白名单内的 IP 才能查询（CoreDNS acl 插件），防止变成开放解析器
- **解锁解析**：ChatGPT / Gemini 等域名解析到指定的解锁 VPS，Gemini 连带谷歌搜索一起解锁（区域一致）
- **节点监控**：每台 DNS 机器的在线状态、今日流量、累计流量
- **解锁检测**：agent 每 10 分钟实测奈飞(含区域/自制剧识别)/YouTube/ChatGPT(出口区域)/Gemini/Disney+ 及 DNS 规则,面板首屏直观显示
- **网页改密码**：登录后可直接修改管理密码
- **集中下发**：面板改解锁 IP、白名单或解锁域名，30 秒内自动同步到所有 DNS 节点
- **域名可配置**：解锁域名（正则）在面板网页上直接编辑，agent 内置列表仅作兜底

## 架构

**集群模式**：每台解锁 VPS 同时跑 CoreDNS + sniproxy，回答自己的公网 IP；所有节点共用一份域名名单、各自回答自己的公网 IP（美国机被问到 ChatGPT 答美国 IP，新加坡机被问到奈飞答新加坡 IP），V2bX 的 dns.json 按组把查询分流到对应节点（如同使用 jpdns01/usdns01）。面板集中管理：统一下发白名单、按节点检测解锁状态、统计每台流量。新增解锁机 = 一键脚本装机 + 面板给该节点填负责域名 + dns.json 加一组。

```
V2bX 节点 ──查询(白名单放行)──▶ DNS机器×N (CoreDNS)
                                  acl: 非白名单 → REFUSED
                                  template: ChatGPT/Gemini 域名 → 解锁VPS IP
                                  其他 → 8.8.8.8 正常解析
                                  ▼
                        Agent(30s): 拉配置 + 上报心跳/流量
                                  ▼
                        面板 (本仓库 panel.py)
```

## 文件说明

| 文件 | 用途 |
|---|---|
| `panel.py` | 面板主程序（FastAPI + SQLite），装在面板机 |
| `agent.py` | DNS 节点 agent，拉配置/生成 Corefile/上报流量，装在每台 DNS 机器 |
| `docker-compose.yml` | DNS 机器上的 CoreDNS 容器 |
| `panel.service` | 面板 systemd 服务（记得改 ADMIN_PASS） |
| `agent.service` | agent systemd 服务（填 PANEL_URL / NODE_TOKEN / NODE_NAME） |

## 部署

### 1. 面板机

```bash
apt update && apt install -y python3 python3-pip git
git clone https://github.com/linglala/dnsjiesuo.git /etc/dnspanel
cd /etc/dnspanel

python3 -m venv venv
venv/bin/pip install fastapi uvicorn python-multipart

cp panel.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now panel

cat initial_password.txt    # 查看自动生成的初始密码
ufw allow 8080              # 或对应防火墙/云安全组放行 8080
```

浏览器打开 `http://面板IP:8080`，用初始密码登录后：设置解锁 VPS IP → 添加节点拿 Token → 加白名单 IP。

> 想自定义密码: `sed -i 's/ADMIN_PASS=changeme/ADMIN_PASS=你的密码/' /etc/systemd/system/panel.service && systemctl daemon-reload && systemctl restart panel`

### 2. 每台 DNS 机器(一键安装)

在面板"添加节点"生成 Token 后,节点表会显示一键命令,直接复制到 DNS 机器上执行即可:

```bash
curl -fsSL https://raw.githubusercontent.com/linglala/dnsjiesuo/main/install.sh | bash -s -- <TOKEN> <面板地址> [节点名]
```

脚本自动完成: 装 docker → 部署 CoreDNS → 部署 agent → 放行 53 端口。

### 3. V2bX 节点接入

节点 `dns.json` 中把 ChatGPT/Gemini 域名的 DNS 指向任意一台 DNS 机器 IP 即可。

## 验证

```bash
# 白名单内的机器:应返回解锁 VPS 的 IP
dig @DNS机器IP chatgpt.com
# 白名单外的机器:应返回 REFUSED
dig @DNS机器IP chatgpt.com
```

## 面板配置项

| 配置 | 位置 |
|---|---|
| 解锁 VPS IP | 面板首页顶部 |
| IP 白名单 | 面板首页（支持 CIDR） |
| 解锁域名 | 各节点本地管理：`/etc/dnspanel/domains.txt`（一行一个域名，留空用内置默认 ChatGPT+Gemini 23 条） |

## 注意事项

- **解锁 VPS 必须做 TLS 中转**（sniproxy / nginx stream 按 SNI 转发 443 到真实目标），否则域名指过去也打不开
- 面板默认 HTTP，建议加域名 + HTTPS 反代后再暴露公网
- 白名单为空时 agent 只允许 127.0.0.1，不会误开放
- ADMIN_PASS 必须改强密码
