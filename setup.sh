#!/usr/bin/env bash
# setup.sh - 一键部署 sing-box (VLESS Reality + TUIC v5)
# 自用 / 分享皆可，请勿商用贩卖节点

set -euo pipefail

#############################
# 基本检查
#############################

if [[ $EUID -ne 0 ]]; then
  echo "请使用 root 运行本脚本（sudo -i 后再执行）"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "正在安装 curl..."
  if command -v apt >/dev/null 2>&1; then
    apt update && apt install -y curl
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl
  else
    echo "未找到 apt 或 yum，请手动安装 curl 后重试。"
    exit 1
  fi
fi

#############################
# 系统与包管理器检测
#############################

OS=""
PKG=""

if [[ -f /etc/debian_version ]]; then
  OS="debian"
  PKG="apt"
elif [[ -f /etc/lsb-release ]]; then
  . /etc/lsb-release
  if [[ "$DISTRIB_ID" == "Ubuntu" ]]; then
    OS="ubuntu"
    PKG="apt"
  fi
elif [[ -f /etc/centos-release ]] || [[ -f /etc/redhat-release ]]; then
  OS="centos"
  PKG="yum"
fi

if [[ -z "$OS" ]]; then
  echo "当前系统暂不支持自动识别，请使用 Debian / Ubuntu。"
  exit 1
fi

echo "检测到系统: $OS"

#############################
# 安装基础依赖
#############################

install_deps() {
  echo "安装基础依赖 (curl, wget, jq, unzip, uuidgen, openssl)..."
  if [[ "$PKG" == "apt" ]]; then
    apt update
    apt install -y wget jq unzip openssl uuid-runtime socat
  else
    yum install -y epel-release || true
    yum install -y wget jq unzip openssl socat
    # CentOS 没有 uuid-runtime，用 uuidgen 看情况
  fi
}

install_deps

if ! command -v jq >/dev/null 2>&1; then
  echo "jq 安装失败，请手动安装 jq 后重试。"
  exit 1
fi

if ! command -v uuidgen >/dev/null 2>&1; then
  echo "uuidgen 不存在，将使用 /proc/sys/kernel/random/uuid 替代..."
fi

#############################
# 获取最新 sing-box
#############################

SING_BOX_BIN="/usr/local/bin/sing-box"
SING_BOX_DIR="/etc/sing-box"
SING_BOX_CONF="$SING_BOX_DIR/config.json"

install_sing_box() {
  if [[ -x "$SING_BOX_BIN" ]]; then
    echo "检测到已安装 sing-box，尝试更新到最新版..."
  else
    echo "开始安装 sing-box..."
  fi

  ARCH_RAW=$(uname -m)
  case "$ARCH_RAW" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "不支持的架构: $ARCH_RAW"; exit 1 ;;
  esac

  echo "检测到架构: $ARCH_RAW ($ARCH)"

  # 获取最新版版本号
  VERSION=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name | sed 's/^v//')
  if [[ -z "$VERSION" || "$VERSION" == "null" ]]; then
    echo "获取 sing-box 最新版本失败，尝试使用固定版本 v1.9.0"
    VERSION="1.9.0"
  fi

  echo "准备安装 sing-box v$VERSION"

  TMP_DIR=$(mktemp -d)
  cd "$TMP_DIR"

  FILE_NAME="sing-box-${VERSION}-linux-${ARCH}.tar.gz"
  DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${FILE_NAME}"

  echo "下载: $DOWNLOAD_URL"
  curl -fSLo "$FILE_NAME" "$DOWNLOAD_URL"

  tar -xzf "$FILE_NAME"
  install "sing-box-${VERSION}-linux-${ARCH}/sing-box" "$SING_BOX_BIN"
  chmod +x "$SING_BOX_BIN"

  mkdir -p "$SING_BOX_DIR"
  cd /
  rm -rf "$TMP_DIR"

  echo "sing-box 安装完成: $SING_BOX_BIN"
}

install_sing_box

#############################
# 生成 Reality 密钥对
#############################

echo "生成 Reality 密钥对..."
REALITY_JSON=$("$SING_BOX_BIN" generate reality-keypair | jq -Rs '
  split("\n") | map(select(length>0)) |
  map(
    if test("Private key:") then
      {"k":"private_key","v": (split("Private key: ")[1])}
    elif test("Public key:") then
      {"k":"public_key","v": (split("Public key: ")[1])}
    else empty end
  ) | from_entries
')

REALITY_PRIVATE_KEY=$(echo "$REALITY_JSON" | jq -r .private_key)
REALITY_PUBLIC_KEY=$(echo "$REALITY_JSON" | jq -r .public_key)

if [[ -z "$REALITY_PRIVATE_KEY" || -z "$REALITY_PUBLIC_KEY" ]]; then
  echo "生成 Reality 密钥失败，请检查 sing-box 是否工作正常。"
  exit 1
fi

# 生成 short_id (8~16位十六进制)
REALITY_SHORT_ID=$(head -c 8 /dev/urandom | xxd -p)

#############################
# 交互：伪装域名 & 端口
#############################

read -rp "请输入 Reality 伪装域名（必须是能正常 443 访问的大站，如 www.apple.com）[默认: www.apple.com]：" REALITY_DOMAIN
REALITY_DOMAIN=${REALITY_DOMAIN:-www.apple.com}

read -rp "VLESS Reality 监听端口 [默认: 443]：" REALITY_PORT
REALITY_PORT=${REALITY_PORT:-443}

# 随机 TUIC 端口（20000-65000）
TUIC_PORT=$(shuf -i 20000-65000 -n 1)

#############################
# 生成 UUID / 密码
#############################

if command -v uuidgen >/dev/null 2>&1; then
  UUID_VLESS=$(uuidgen)
  UUID_TUIC=$(uuidgen)
else
  UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
  UUID_TUIC=$(cat /proc/sys/kernel/random/uuid)
fi

TUIC_PASSWORD=$(openssl rand -hex 16)

#############################
# 获取服务器 IP
#############################

SERVER_IP4=$(curl -fsSL ipv4.ip.sb 2>/dev/null || curl -fsSL https://api.ipify.org 2>/dev/null || echo "your_server_ip")

#############################
# 写入 sing-box 配置
#############################

cat > "$SING_BOX_CONF" <<EOF
{
  "log": {
    "level": "info"
  },
  "dns": {
    "servers": [
      {
        "tag": "dns-remote",
        "address": "https://1.1.1.1/dns-query",
        "detour": "direct"
      }
    ]
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": ${REALITY_PORT},
      "users": [
        {
          "uuid": "${UUID_VLESS}",
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
            "${REALITY_SHORT_ID}"
          ]
        }
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": ${TUIC_PORT},
      "users": [
        {
          "uuid": "${UUID_TUIC}",
          "password": "${TUIC_PASSWORD}"
        }
      ],
      "congestion_control": "bbr",
      "zero_rtt_handshake": true,
      "heartbeat": "10s",
      "tls": {
        "enabled": true,
        "server_name": "${REALITY_DOMAIN}",
        "alpn": [
          "h3",
          "spdy/3.1"
        ]
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
  ]
}
EOF

echo "配置文件已生成: $SING_BOX_CONF"

#############################
# systemd 服务
#############################

SERVICE_FILE="/etc/systemd/system/sing-box.service"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Sing-box Service
After=network.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=${SING_BOX_BIN} run -c ${SING_BOX_CONF}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sing-box
systemctl restart sing-box

sleep 1
if ! systemctl is-active --quiet sing-box; then
  echo "sing-box 启动失败，请执行 'journalctl -u sing-box -e' 查看日志。"
  exit 1
fi

#############################
# 开启 BBR
#############################

enable_bbr() {
  echo "开启 TCP BBR 拥塞控制..."
  SYSCTL_CONF="/etc/sysctl.conf"
  grep -q "net.core.default_qdisc=fq" "$SYSCTL_CONF" 2>/dev/null || echo "net.core.default_qdisc=fq" >> "$SYSCTL_CONF"
  grep -q "net.ipv4.tcp_congestion_control=bbr" "$SYSCTL_CONF" 2>/dev/null || echo "net.ipv4.tcp_congestion_control=bbr" >> "$SYSCTL_CONF"
  sysctl -p >/dev/null 2>&1 || true
}

enable_bbr

#############################
# 输出节点信息
#############################

echo
echo "================= 部署完成 ================="
echo
echo "服务器 IP: ${SERVER_IP4}"
echo "Reality 伪装域名: ${REALITY_DOMAIN}"
echo "VLESS 端口: ${REALITY_PORT}"
echo "TUIC 端口:  ${TUIC_PORT}"
echo

echo "---------- VLESS Reality 节点 ----------"
VLESS_LINK="vless://${UUID_VLESS}@${SERVER_IP4}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp&headerType=none#VLESS-REALITY"
echo "${VLESS_LINK}"
echo

echo "---------- TUIC v5 节点 ----------"
TUIC_LINK="tuic://${UUID_TUIC}:${TUIC_PASSWORD}@${SERVER_IP4}:${TUIC_PORT}?congestion_control=bbr&alpn=h3&sni=${REALITY_DOMAIN}#TUIC-v5"
echo "${TUIC_LINK}"
echo

echo "提示："
echo "1. VLESS Reality 节点可导入 sing-box / v2rayN / NekoBox 等客户端。"
echo "2. TUIC v5 节点可导入 NekoBox / sing-box / clash-meta（需 tuic v5 支持）。"
echo "3. 如需修改配置，请编辑: ${SING_BOX_CONF} 后执行: systemctl restart sing-box"
echo
echo "祝使用愉快，注意仅限自用，勿滥用。"
echo "==========================================="