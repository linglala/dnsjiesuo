#!/usr/bin/env bash
# DNS 解锁节点一键安装: 安装 CoreDNS + nginx(SNI转发) + agent 并接入面板
# 用法: curl -fsSL https://raw.githubusercontent.com/linglala/dnsjiesuo/main/install.sh | bash -s -- <TOKEN> <面板地址> [节点名]
set -e

TOKEN="${1:-$NODE_TOKEN}"
PANEL="${2:-$PANEL_URL}"
NAME="${3:-$(hostname)}"

REPO="https://raw.githubusercontent.com/linglala/dnsjiesuo/main"

# 地址补协议头
case "$PANEL" in
    http://*|https://*) ;;
    *) PANEL="http://$PANEL" ;;
esac

if [ -z "$TOKEN" ] || [ -z "$PANEL" ]; then
    echo "用法: install.sh <TOKEN> <面板地址如 http://1.2.3.4:8080> [节点名]"
    exit 1
fi
echo "==> 节点名: $NAME  面板: $PANEL"

# 1. docker
if ! command -v docker >/dev/null 2>&1; then
    echo "==> 安装 docker..."
    curl -fsSL https://get.docker.com | sh
fi

# 2. CoreDNS
echo "==> 部署 CoreDNS..."
mkdir -p /etc/coredns
# 防止 Docker 把不存在的挂载点建成目录
if [ -d /etc/coredns/Corefile ]; then
    echo "==> 发现 /etc/coredns/Corefile 是目录(旧bug残留), 修复..."
    rm -rf /etc/coredns/Corefile
fi
touch /etc/coredns/Corefile
cd /etc/coredns
if [ ! -f docker-compose.yml ]; then
    curl -fsSL -o docker-compose.yml "$REPO/docker-compose.yml"
fi
docker compose up -d

# 3. nginx SNI 转发 (443 -> 真实站点)
if ! command -v nginx >/dev/null 2>&1; then
    echo "==> 安装 nginx..."
    apt-get update -qq
    apt-get install -y -qq nginx libnginx-mod-stream || apt-get install -y -qq nginx
fi
mkdir -p /etc/nginx/stream.d
if ! grep -q "stream.d" /etc/nginx/nginx.conf 2>/dev/null; then
    # 在主配置的 http 块之前注入 stream 配置(awk 注入,避免 sed 多行转义问题)
    awk '/^http \{/{print "stream {"; print "    include /etc/nginx/stream.d/*.conf;"; print "}"}1' \
        /etc/nginx/nginx.conf > /tmp/nginx.conf.new \
        && mv /tmp/nginx.conf.new /etc/nginx/nginx.conf
fi
if [ ! -f /etc/nginx/stream.d/unlock.conf ]; then
    echo "==> 写入 SNI 转发配置..."
    cat > /etc/nginx/stream.d/unlock.conf <<'EOF'
# DNS 解锁 SNI 转发: 按客户端 SNI 域名直连真实目标
# 注意: 本文件被 include 在 nginx.conf 的 stream{} 容器内, 不要再包一层 stream{}
# resolver 必须用干净的上游(1.1.1.1), 不能用本机 CoreDNS —— 否则解锁域名
# 会被解析回自己, 形成回环!
resolver 1.1.1.1 8.8.8.8 valid=30s;
server {
    listen 443;
    ssl_preread on;
    proxy_pass $ssl_preread_server_name:443;
    proxy_connect_timeout 10s;
}
EOF
fi
nginx -t && systemctl restart nginx
systemctl enable nginx 2>/dev/null || true

# 4. agent
echo "==> 部署 agent..."
mkdir -p /etc/dnspanel
# 种子域名表: 补 agent 内置名单没有的(Gemini扩展+流媒体), 已有文件不覆盖
if [ ! -f /etc/dnspanel/domains.txt ]; then
    echo "==> 写入种子域名表(流媒体+Gemini扩展)..."
    cat > /etc/dnspanel/domains.txt <<'EOF'
ai.google.dev
aistudio.google.com
accounts.google.com
netflix.com
netflix.ca
netflix.net
nflxext.com
nflximg.com
nflximg.net
nflxsearch.net
nflxso.net
nflxvideo.net
disneyplus.com
disney-plus.net
disneystreaming.com
dssott.com
bamgrid.com
EOF
fi
curl -fsSL -o /etc/dnspanel/agent.py "$REPO/agent.py"

cat > /etc/systemd/system/agent.service <<EOF
[Unit]
Description=DNS Unlock Agent
After=network.target

[Service]
Environment=PANEL_URL=$PANEL
Environment=NODE_TOKEN=$TOKEN
Environment=NODE_NAME=$NAME
ExecStart=/usr/bin/python3 /etc/dnspanel/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now agent

# 5. 防火墙(尽力而为,不支持的系统跳过)
(ufw allow 53/tcp && ufw allow 53/udp && ufw allow 443/tcp) 2>/dev/null || true

echo ""
echo "==> 安装完成!"
echo "    查看日志: journalctl -u agent -f"
echo "    Corefile: cat /etc/coredns/Corefile"
echo "    验证:     dig @127.0.0.1 chatgpt.com +short"
echo "              curl -sk --resolve chatgpt.com:443:\$(curl -4 -s ifconfig.me) https://chatgpt.com/cdn-cgi/trace | grep loc="
echo "    几分钟后到面板确认该节点在线"
