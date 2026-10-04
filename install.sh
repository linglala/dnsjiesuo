#!/usr/bin/env bash
# DNS 解锁节点一键安装: 安装 CoreDNS + agent 并接入面板
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

# 3. agent
echo "==> 部署 agent..."
mkdir -p /etc/dnspanel
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

# 4. 防火墙(尽力而为,不支持的系统跳过)
(ufw allow 53/tcp && ufw allow 53/udp) 2>/dev/null || true

echo ""
echo "==> 安装完成!"
echo "    查看日志: journalctl -u agent -f"
echo "    Corefile: cat /etc/coredns/Corefile"
echo "    几分钟后到面板确认该节点在线"
