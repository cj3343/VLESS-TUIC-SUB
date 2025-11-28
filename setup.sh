#!/usr/bin/env bash
# VLESS-REALITY + TUIC 一键脚本 v1.4
# 特性：
# 1）自动安装 sing-box（Debian / Ubuntu）
# 2）从你的 Gist 拉取 Reality 域名池，支持重测 & 手动输入
# 3）一次性生成 VLESS Reality + TUIC v5 节点
# 4）自动生成 vless:// & tuic:// 分享链接 + 终端二维码 + PNG 二维码

set -e

# ========== 工具函数 ==========
COLOR_RESET="\033[0m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_RED="\033[31m"
COLOR_BLUE="\033[36m"

log()  { echo -e "${COLOR_GREEN}[INFO]${COLOR_RESET} $*"; }
warn() { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"; }
err()  { echo -e "${COLOR_RED}[ERR ]${COLOR_RESET}  $*"; }

# ========== 环境检查 ==========
if [ "$(id -u)" -ne 0 ]; then
  err "请用 root 权限执行：sudo bash setup.sh"
  exit 1
fi

if ! command -v systemctl &>/dev/null; then
  err "当前系统没有 systemd，暂不支持（需要 systemctl）。"
  exit 1
fi

if [ ! -f /etc/debian_version ]; then
  warn "当前不是 Debian/Ubuntu，脚本按 Debian 系写的，可能会失败。"
fi

log "更新软件源 & 安装依赖：curl wget tar jq openssl ssl-cert qrencode..."
apt-get update -y
apt-get install -y curl wget tar jq openssl ssl-cert qrencode

# ========== 安装 sing-box ==========
SINGBOX_VERSION="1.12.12"
SINGBOX_BIN="/usr/local/bin/sing-box"

install_singbox() {
  if command -v sing-box &>/dev/null; then
    log "已检测到 sing-box：$(sing-box version 2>/dev/null || echo 已安装)，跳过安装。"
    return
  fi

  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64)  SB_ARCH="amd64" ;;
    aarch64|arm64) SB_ARCH="arm64" ;;
    *)
      err "暂不支持架构：$ARCH"
      exit 1
      ;;
  esac

  log "开始安装 sing-box v${SINGBOX_VERSION} (${SB_ARCH})..."
  URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}.tar.gz"

  TMP_DIR=$(mktemp -d)
  cd "$TMP_DIR"
  wget -O sing-box.tar.gz "$URL"
  tar -xzf sing-box.tar.gz
  cd "sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}"

  install -m 755 sing-box "$SINGBOX_BIN"
  cd /
  rm -rf "$TMP_DIR"

  log "sing-box 安装完成：$SINGBOX_BIN"
}

install_singbox

# ========== 域名池：从你的 Gist 获取 ==========
GIST_URL="https://gist.githubusercontent.com/cj3343/8d38d603440ea50105319d7c09909faf/raw/47e05fcfdece890d1480f462afadc0baffcbb120/domain-list.txt"

get_domain_pool() {
  local dl
  log "从 Gist 获取 Reality 域名池..."
  if dl=$(curl -fsSL "$GIST_URL"); then
    echo "$dl"
  else
    warn "从 Gist 获取域名池失败，使用内置备用域名列表。"
    cat <<EOF
www.apple.com
www.microsoft.com
www.google.com
www.cloudflare.com
www.amazon.com
www.netflix.com
www.spotify.com
www.tesla.com
www.nvidia.com
electronics.sony.com
www.oracle.com
www.bing.com
EOF
  fi
}

# ========== Reality 伪装域名选择（支持重测 & 手动输入） ==========
select_reality_domain() {
  local domain_list
  domain_list=$(get_domain_pool)

  while true; do
    echo
    log "开始测试 Reality 目标域名延迟（openssl + 443）..."

    local best_domain=""
    local best_rtt=999999

    # 随机抽 10 个（不够 10 个就全测）
    local domains
    domains=$(printf "%s\n" "$domain_list" | shuf | head -n 10)

    while read -r d; do
      [ -z "$d" ] && continue
      local t1 t2 rtt
      t1=$(date +%s%3N)
      if timeout 1 openssl s_client -connect "$d:443" -servername "$d" </dev/null &>/dev/null; then
        t2=$(date +%s%3N)
        rtt=$((t2 - t1))
        echo "  $d: ${rtt} ms"
        if [ "$rtt" -lt "$best_rtt" ]; then
          best_rtt=$rtt
          best_domain=$d
        fi
      else
        echo "  $d: timeout"
      fi
    done <<< "$domains"

    if [ -z "$best_domain" ]; then
      warn "本轮测试没有可用域名（全部超时），你可以：2) 再测一轮 或 3) 手动输入。"
    else
      log "✅ 本轮选中的最低延迟域名：${best_domain} (${best_rtt} ms)"
    fi

    echo
    echo "请选择 Reality 伪装域名的处理方式："
    echo "  1) 使用这个域名（${best_domain:-当前无结果}）"
    echo "  2) 重新测试一轮（从 Gist 域名池重新抽样）"
    echo "  3) 手动输入伪装域名（例如：www.apple.com）"
    read -rp "请输入选项 [1/2/3，默认 1]: " choice
    choice=${choice:-1}

    case "$choice" in
      1)
        if [ -z "$best_domain" ]; then
          warn "当前没有可用域名，请选择 2) 或 3)。"
          continue
        fi
        REALITY_DOMAIN="$best_domain"
        break
        ;;
      2)
        log "重新从 Gist 拉取并测试一轮 Reality 域名..."
        domain_list=$(get_domain_pool)
        continue
        ;;
      3)
        read -rp "请输入自定义 Reality 伪装域名（必须能 443 正常访问）： " manual_domain
        if [ -z "$manual_domain" ]; then
          warn "输入为空，回到选择菜单。"
          continue
        fi
        REALITY_DOMAIN="$manual_domain"
        break
        ;;
      *)
        warn "输入无效，默认使用当前测试结果域名。"
        REALITY_DOMAIN="$best_domain"
        break
        ;;
    esac
  done

  log "✅ 最终使用的 Reality 伪装域名：${REALITY_DOMAIN}"
}

select_reality_domain

# ========== 端口 & ID 生成 ==========
read -rp "VLESS Reality 端口 [默认: 443]: " VLESS_PORT
VLESS_PORT=${VLESS_PORT:-443}

read -rp "TUIC 端口 [默认: 8443]: " TUIC_PORT
TUIC_PORT=${TUIC_PORT:-8443}

log "✅ VLESS 端口: ${VLESS_PORT}"
log "✅ TUIC  端口: ${TUIC_PORT}"

UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
UUID_TUIC=$(cat /proc/sys/kernel/random/uuid)
TUIC_PASSWORD=$(openssl rand -base64 12 | tr -d '=+/')

log "生成 Reality 密钥对..."
cd /etc || mkdir -p /etc && cd /etc
mkdir -p /etc/sing-box
cd /etc/sing-box

# 备份老配置
if [ -f config.json ]; then
  cp config.json "config.json.bak-$(date +%s)"
  warn "已备份旧 config.json 为 config.json.bak-时间戳"
fi

REALITY_RAW=$("$SINGBOX_BIN" generate reality-keypair)
REALITY_PRIVATE_KEY=$(echo "$REALITY_RAW" | awk '/PrivateKey/ {print $2}')
REALITY_PUBLIC_KEY=$(echo "$REALITY_RAW" | awk '/PublicKey/ {print $2}')

if [ -z "$REALITY_PRIVATE_KEY" ] || [ -z "$REALITY_PUBLIC_KEY" ]; then
  err "生成 Reality 密钥失败，请检查 sing-box 版本。"
  exit 1
fi

cat > reality.txt <<EOF
PrivateKey: ${REALITY_PRIVATE_KEY}
PublicKey: ${REALITY_PUBLIC_KEY}
EOF

log "Reality 密钥已保存到 /etc/sing-box/reality.txt"

# 生成一个短 ID（16 hex）
REALITY_SHORT_ID=$(openssl rand -hex 8)

# ========== 写入 sing-box 配置 ==========
log "写入 /etc/sing-box/config.json ..."

cat > /etc/sing-box/config.json <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "223.5.5.5",
        "detour": "direct"
      },
      {
        "tag": "google",
        "address": "8.8.8.8",
        "detour": "direct"
      }
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
      "tag": "tuic",
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
        "server_name": "cp.cloudflare.com",
        "alpn": [
          "h3"
        ],
        "certificate_path": "/etc/ssl/certs/ssl-cert-snakeoil.pem",
        "key_path": "/etc/ssl/private/ssl-cert-snakeoil.key"
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
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "geoip": [
          "cn"
        ],
        "outbound": "direct"
      }
    ],
    "final": "direct"
  }
}
EOF

log "配置写入完成，检查 JSON 合法性..."
"$SINGBOX_BIN" check -c /etc/sing-box/config.json || {
  err "配置检查失败，请手动修复 /etc/sing-box/config.json 后重试。"
  exit 1
}

# ========== 写 systemd 服务 ==========
log "写入 /etc/systemd/system/sing-box.service ..."

cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=${SINGBOX_BIN} -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sing-box

sleep 1
if ! systemctl is-active --quiet sing-box; then
  err "sing-box 启动失败，请执行：journalctl -u sing-box -e 查看日志。"
  exit 1
fi

log "✅ sing-box 已启动。"

# ========== 生成分享链接 ==========
log "生成分享链接（vless:// & tuic://）..."

IPV4=$(curl -4s https://api64.ipify.org || curl -4s https://api.ip.sb || curl -4s ifconfig.me || true)
if [ -z "$IPV4" ]; then
  warn "自动获取公网 IPv4 失败，需要手动输入。"
  read -rp "请输入服务器公网 IPv4: " IPV4
fi

VLESS_URL="vless://${UUID_VLESS}@${IPV4}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#VLESS-REALITY"
TUIC_URL="tuic://${UUID_TUIC}:${TUIC_PASSWORD}@${IPV4}:${TUIC_PORT}?congestion_control=bbr&sni=cp.cloudflare.com&alpn=h3#TUIC"

echo
echo "================= VLESS Reality 链接 ================="
echo "$VLESS_URL"
echo "====================================================="
echo
echo "================= TUIC 链接 ========================="
echo "$TUIC_URL"
echo "====================================================="
echo

# ========== 生成终端二维码 + PNG 文件 ==========
QR_DIR="/root/singbox-qrcode"
mkdir -p "$QR_DIR"

log "生成终端二维码（适合直接拿手机扫一扫）..."
echo
echo "==== VLESS Reality · 终端二维码 ===="
qrencode -t ANSIUTF8 "$VLESS_URL" || warn "qrencode 生成 VLESS 终端二维码失败"
echo
echo "==== TUIC · 终端二维码 ===="
qrencode -t ANSIUTF8 "$TUIC_URL" || warn "qrencode 生成 TUIC 终端二维码失败"
echo

log "生成 PNG 格式二维码（保存在 ${QR_DIR}）..."
qrencode -o "${QR_DIR}/vless-reality.png" "$VLESS_URL"  || warn "生成 vless-reality.png 失败"
qrencode -o "${QR_DIR}/tuic.png"          "$TUIC_URL"   || warn "生成 tuic.png 失败"

echo
log "全部完成！"
echo -e "${COLOR_BLUE}提示：${COLOR_RESET}"
echo "1）安卓 NekoBox / NapsternetV：直接扫码终端二维码，或导入 vless:// / tuic:// 链接；"
echo "2）Mac / PC：复制链接粘贴到 Clash / sing-box GUI / Nekoray；"
echo "3）二维码 PNG：在 ${QR_DIR} 目录下，可用 SFTP 下载后发给朋友或贴到文档。"
