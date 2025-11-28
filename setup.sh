#!/usr/bin/env bash
# VLESS-REALITY + TUIC 一键脚本 v1.2（兼容 sing-box 1.12.x）
# 作者：你（cj3343）+ ChatGPT 联合踩坑版

set -euo pipefail

#=========== 工具函数 ===========#

log()  { echo -e "\e[32m[INFO]\e[0m $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m $*"; }
err()  { echo -e "\e[31m[ERR ]\e[0m $*"; }

#=========== 环境检查 ===========#

if ! command -v curl >/dev/null 2>&1; then
  log "安装 curl ..."
  apt-get update -y && apt-get install -y curl
fi

if ! command -v openssl >/dev/null 2>&1; then
  log "安装 openssl ..."
  apt-get update -y && apt-get install -y openssl
fi

if ! command -v tar >/dev/null 2>&1; then
  log "安装 tar ..."
  apt-get update -y && apt-get install -y tar
fi

if ! command -v systemctl >/dev/null 2>&1; then
  err "当前系统没有 systemd（systemctl），不适合作为这个脚本的目标系统。"
  exit 1
fi

#=========== 清理旧配置 ===========#

log "停止旧 sing-box 服务（如果有）..."
systemctl stop sing-box 2>/dev/null || true

log "创建 /etc/sing-box 目录，并清空旧配置..."
mkdir -p /etc/sing-box
rm -f /etc/sing-box/config.json \
      /etc/sing-box/reality.txt \
      /etc/sing-box/tuic_cert.pem \
      /etc/sing-box/tuic_key.pem

#=========== 安装 sing-box ===========#

SING_BOX_VERSION="1.12.12"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  SB_ARCH="amd64" ;;
  aarch64|arm64) SB_ARCH="arm64" ;;
  *)
    err "暂不支持的 CPU 架构: $ARCH"
    exit 1
    ;;
esac

if ! command -v sing-box >/dev/null 2>&1; then
  log "开始安装 sing-box ${SING_BOX_VERSION} (${SB_ARCH}) ..."
  URL="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${SB_ARCH}.tar.gz"
  cd /tmp
  curl -L -o sing-box.tar.gz "$URL"
  tar xf sing-box.tar.gz
  cd "sing-box-${SING_BOX_VERSION}-linux-${SB_ARCH}"
  install -m 755 sing-box /usr/local/bin/sing-box
  log "sing-box 安装完成: /usr/local/bin/sing-box"
else
  log "已检测到 sing-box，跳过安装。"
fi

#=========== 自动选 Reality 伪装域名 ===========#

GIST_URL="https://gist.githubusercontent.com/cj3343/8d38d603440ea50105319d7c09909faf/raw/74ab1e5c3cd93a94ecfb8227bdc0db136228c9eb/domain-list.txt"

log "从域名池获取候选大站列表..."
domain_list=$(curl -s "$GIST_URL" || true)

if [ -z "$domain_list" ]; then
  warn "获取域名池失败，回落到内置备选列表。"
  domain_list=$'www.apple.com\nnvidia.com\nwww.microsoft.com\nwww.google.com'
fi

# 随机取 8~10 个域名测延迟
domains=$(printf "%s\n" "$domain_list" | shuf | head -n 10)

log "开始测试 Reality 目标域名延迟（openssl + 443）..."

best_domain=""
best_rtt=999999

for d in $domains; do
  t1=$(date +%s%3N)
  if timeout 1 openssl s_client -connect "${d}:443" -servername "$d" </dev/null &>/dev/null; then
    t2=$(date +%s%3N)
    rtt=$((t2 - t1))
    echo "  $d: ${rtt} ms"
    if [ "$rtt" -lt "$best_rtt" ]; then
      best_rtt=$rtt
      best_domain="$d"
    fi
  else
    echo "  $d: timeout"
  fi
done

if [ -z "$best_domain" ]; then
  warn "所有测试都超时，使用默认伪装域名 www.apple.com"
  best_domain="www.apple.com"
else
  log "✅ 选中的最低延迟域名：${best_domain} (${best_rtt} ms)"
fi

read -rp "Reality 伪装域名 [回车使用自动选择: ${best_domain}]：" REALITY_DOMAIN
REALITY_DOMAIN=${REALITY_DOMAIN:-$best_domain}
log "✅ 最终使用的伪装域名：${REALITY_DOMAIN}"

#=========== 端口 & UUID & Reality 密钥 ===========#

read -rp "VLESS Reality 端口 [默认: 443]：" VLESS_PORT
VLESS_PORT=${VLESS_PORT:-443}

read -rp "TUIC 端口 [默认: 8443]：" TUIC_PORT
TUIC_PORT=${TUIC_PORT:-8443}

log "✅ VLESS 端口: ${VLESS_PORT}"
log "✅ TUIC  端口: ${TUIC_PORT}"

# 生成 UUID
log "👉 生成 VLESS / TUIC UUID ..."
VLESS_UUID=$(cat /proc/sys/kernel/random/uuid)
TUIC_UUID=$(cat /proc/sys/kernel/random/uuid)

# TUIC 用户密码（16 字节随机）
TUIC_PASSWORD=$(openssl rand -hex 16)

# 生成 Reality 密钥对（兼容旧版：用文本输出）
log "👉 生成 Reality 密钥对 ..."
cd /etc/sing-box
sing-box generate reality-keypair > reality.txt

REALITY_PRIVATE_KEY=$(grep -i 'PrivateKey' reality.txt | awk '{print $2}')
REALITY_PUBLIC_KEY=$(grep -i 'PublicKey' reality.txt | awk '{print $2}')

if [ -z "$REALITY_PRIVATE_KEY" ] || [ -z "$REALITY_PUBLIC_KEY" ]; then
  err "读取 Reality 密钥失败，请检查 reality.txt。"
  exit 1
fi

# short_id 8 字节 hex（16 字符）
SHORT_ID=$(openssl rand -hex 8)

log "✅ Reality PrivateKey: ${REALITY_PRIVATE_KEY}"
log "✅ Reality PublicKey : ${REALITY_PUBLIC_KEY}"
log "✅ Reality ShortID   : ${SHORT_ID}"

#=========== 自签 TUIC TLS 证书 ===========#

log "👉 为 TUIC 生成自签 TLS 证书（10年有效）..."
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout /etc/sing-box/tuic_key.pem \
  -out /etc/sing-box/tuic_cert.pem \
  -days 3650 \
  -subj "/CN=${REALITY_DOMAIN}" >/dev/null 2>&1

#=========== 生成 sing-box 配置 ===========#

log "👉 写入 /etc/sing-box/config.json ..."

cat >/etc/sing-box/config.json <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      "https://8.8.8.8/dns-query",
      "https://1.1.1.1/dns-query"
    ]
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": ${VLESS_PORT},
      "users": [
        {
          "uuid": "${VLESS_UUID}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${REALITY_DOMAIN}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${REALITY_DOMAIN}",
            "server_port": 443
          },
          "private_key": "${REALITY_PRIVATE_KEY}",
          "short_id": [
            "${SHORT_ID}"
          ]
        }
      }
    },
    {
      "type": "tuic",
      "tag": "tuic",
      "listen": "::",
      "listen_port": ${TUIC_PORT},
      "users": [
        {
          "uuid": "${TUIC_UUID}",
          "password": "${TUIC_PASSWORD}"
        }
      ],
      "congestion_control": "bbr",
      "udp_relay_mode": "native",
      "zero_rtt_handshake": true,
      "tls": {
        "enabled": true,
        "server_name": "${REALITY_DOMAIN}",
        "certificate_path": "/etc/sing-box/tuic_cert.pem",
        "key_path": "/etc/sing-box/tuic_key.pem"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "rules": [
      {
        "geosite": [
          "cn"
        ],
        "geoip": [
          "cn"
        ],
        "outbound": "direct"
      },
      {
        "geoip": [
          "private"
        ],
        "outbound": "direct"
      }
    ],
    "final": "direct"
  }
}
EOF

#=========== systemd 服务 ===========#

log "👉 写入 /etc/systemd/system/sing-box.service ..."

cat >/etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service
After=network.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sing-box >/dev/null 2>&1 || true

log "启动 sing-box ..."
systemctl restart sing-box

sleep 2
if ! systemctl is-active --quiet sing-box; then
  err "sing-box 启动失败，请执行 'journalctl -u sing-box -e' 查看日志。"
  exit 1
fi

log "✅ sing-box 已启动：VLESS ${VLESS_PORT} / TUIC ${TUIC_PORT}"

#=========== 生成 vless:// & tuic:// 链接 ===========#

# 取服务器公网 IPv4
IPV4=$(curl -4s https://api-ipv4.ip.sb || curl -4s ifconfig.me || echo "YOUR_SERVER_IP")

VLESS_URL="vless://${VLESS_UUID}@${IPV4}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp#VLESS-REALITY"

TUIC_URL="tuic://${TUIC_UUID}:${TUIC_PASSWORD}@${IPV4}:${TUIC_PORT}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#TUIC"

echo
echo "================= VLESS Reality 链接 ================="
echo "$VLESS_URL"
echo "====================================================="
echo
echo "=================== TUIC 链接 ========================"
echo "$TUIC_URL"
echo "====================================================="
echo
log "全部完成！"
echo "提示："
echo "1）安卓 NekoBox：直接粘贴 vless:// 或 tuic:// 链接导入即可；"
echo "2）Mac Surge / sing-box / Nekoray：新建节点 → 粘贴链接导入；"
echo "3）下次重装：直接重新运行本脚本，旧 config.json / reality.txt 等会自动覆盖。"
echo
