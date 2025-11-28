#!/usr/bin/env bash
# VLESS-REALITY + TUIC 一键脚本 v2
# 适用：Debian / Ubuntu，x86_64 / arm64

set -e

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
RESET="\033[0m"

log() { echo -e "${GREEN}[INFO]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
err() { echo -e "${RED}[ERR ]${RESET} $*"; }

###################################
# 0. 基础检查
###################################
check_root() {
  if [ "$EUID" -ne 0 ]; then
    err "请使用 root 运行本脚本（sudo -i 或 sudo bash setup.sh）"
    exit 1
  fi
}

check_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
      debian|ubuntu)
        log "检测到系统: $PRETTY_NAME"
        ;;
      *)
        warn "检测到系统: $PRETTY_NAME，本脚本主要针对 Debian/Ubuntu，其他系统可能不兼容。"
        ;;
    esac
  fi
}

###################################
# 1. 安装依赖 + 最新 sing-box
###################################
install_deps() {
  log "更新系统并安装依赖（curl / wget / jq / qrencode / openssl）..."
  apt-get update -y
  apt-get install -y curl wget jq qrencode openssl ca-certificates
}

install_sing_box() {
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64) SB_ARCH="amd64" ;;
    aarch64|arm64) SB_ARCH="arm64" ;;
    *)
      err "不支持的 CPU 架构: $ARCH"
      exit 1
      ;;
  esac

  log "检测并安装最新 sing-box ..."
  LATEST=$(curl -fsSL "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r '.tag_name')
  if [ -z "$LATEST" ] || [ "$LATEST" = "null" ]; then
    err "获取 sing-box 最新版本号失败，请稍后重试。"
    exit 1
  fi

  SB_URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST}/sing-box-${LATEST}-linux-${SB_ARCH}.tar.gz"
  log "下载并安装 sing-box ${LATEST} (${SB_ARCH}) ..."
  cd /tmp
  wget -O sb.tar.gz "$SB_URL"
  tar -xzf sb.tar.gz
  install -m 755 sing-box*/sing-box /usr/local/bin/sing-box
  rm -rf sing-box* sb.tar.gz

  log "sing-box 安装完成: $(sing-box version)"
}

###################################
# 2. Reality 域名延迟测试（域名池）
###################################
GIST_URL="https://gist.githubusercontent.com/cj3343/8d38d603440ea50105319d7c09909faf/raw/47e05fcfdece890d1480f462afadc0baffcbb120/domain-list.txt"

test_reality_domain() {
  local TRY_COUNT=${1:-10}
  log "开始测试 Reality 目标域名延迟（openssl + 443，随机 $TRY_COUNT 个）..."

  local domain_list
  domain_list=$(curl -fsSL "$GIST_URL" 2>/dev/null || true)
  if [ -z "$domain_list" ]; then
    err "从 Gist 获取域名池失败，请检查网络或 Gist 地址。"
    return 1
  fi

  local domains
  # 随机选 TRY_COUNT 个
  domains=$(printf "%s\n" "$domain_list" | shuf | head -n "$TRY_COUNT")

  local best_domain=""
  local best_rtt=999999

  while read -r d; do
    [ -z "$d" ] && continue
    local t1 t2 diff
    t1=$(date +%s%3N)
    if timeout 1 openssl s_client -connect "$d:443" -servername "$d" </dev/null &>/dev/null; then
      t2=$(date +%s%3N)
      diff=$((t2 - t1))
      printf "  %-30s %4s ms\n" "$d:" "$diff"
      if [ "$diff" -lt "$best_rtt" ]; then
        best_rtt=$diff
        best_domain="$d"
      fi
    else
      printf "  %-30s %s\n" "$d:" "timeout"
    fi
  done <<< "$domains"

  if [ -z "$best_domain" ]; then
    warn "本轮测试全部 timeout。"
    return 2
  fi

  log "✅ 本轮最低延迟域名：${best_domain} (${best_rtt} ms)"
  BEST_DOMAIN="$best_domain"
  BEST_RTT="$best_rtt"
  return 0
}

choose_reality_domain() {
  local final_domain=""
  while true; do
    if test_reality_domain 10; then
      echo
      echo -e "${BLUE}当前最低延迟：${BEST_DOMAIN} (${BEST_RTT} ms)${RESET}"
      echo "请选择："
      echo "  1) 直接使用这个域名"
      echo "  2) 再随机测速一轮"
      echo "  3) 手动输入域名（例如 www.apple.com）"
      read -rp "请输入选项 [1/2/3，默认 1]: " choice
      choice=${choice:-1}
      case "$choice" in
        1)
          final_domain="$BEST_DOMAIN"
          ;;
        2)
          continue
          ;;
        3)
          read -rp "请输入自定义域名（确保 443 可访问）： " manual_domain
          if [ -n "$manual_domain" ]; then
            final_domain="$manual_domain"
          else
            warn "输入为空，将重新测速。"
            continue
          fi
          ;;
        *)
          warn "无效选项，默认使用 ${BEST_DOMAIN}。"
          final_domain="$BEST_DOMAIN"
          ;;
      esac
    else
      echo
      warn "测速失败或全部 timeout。"
      read -rp "请输入自定义域名（例如 www.apple.com），直接回车重新测速： " manual_domain
      if [ -n "$manual_domain" ]; then
        final_domain="$manual_domain"
      else
        continue
      fi
    fi

    [ -n "$final_domain" ] && break
  done

  REALITY_DOMAIN="$final_domain"
  log "✅ 最终使用的 Reality 伪装域名：${REALITY_DOMAIN}"
}

###################################
# 3. 交互输入端口 + 生成参数
###################################
ask_ports_and_params() {
  read -rp "VLESS Reality 端口 [默认: 443]: " VLESS_PORT
  VLESS_PORT=${VLESS_PORT:-443}

  read -rp "TUIC 端口 [默认: 8443]: " TUIC_PORT
  TUIC_PORT=${TUIC_PORT:-8443}

  log "✅ VLESS 端口: ${VLESS_PORT}"
  log "✅ TUIC  端口: ${TUIC_PORT}"

  UUID=$(cat /proc/sys/kernel/random/uuid)
  TUIC_PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
  SHORT_ID=$(openssl rand -hex 8)

  log "生成 UUID: ${UUID}"
  log "生成 TUIC 密码: ${TUIC_PASSWORD}"
  log "生成 Reality Short ID: ${SHORT_ID}"
}

###################################
# 4. 生成 Reality 密钥对 + 写 config.json
###################################
prepare_config() {
  mkdir -p /etc/sing-box
  cd /etc/sing-box

  if [ -f config.json ]; then
    local bak="config.json.bak-$(date +%Y%m%d-%H%M%S)"
    warn "检测到已有 /etc/sing-box/config.json，备份为 ${bak}"
    cp config.json "$bak"
  fi

  log "生成 Reality 密钥对..."
  sing-box generate reality-keypair > reality.txt
  PRIVATE_KEY=$(grep -i 'PrivateKey' reality.txt | awk '{print $2}')
  PUBLIC_KEY=$(grep -i 'PublicKey' reality.txt | awk '{print $2}')

  log "Reality 私钥: ${PRIVATE_KEY}"
  log "Reality 公钥: ${PUBLIC_KEY}"

  log "写入 /etc/sing-box/config.json ..."
  cat > /etc/sing-box/config.json <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      "https://1.1.1.1/dns-query",
      "tls://8.8.8.8:853",
      "local"
    ]
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": ${VLESS_PORT},
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "uuid": "${UUID}",
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
          "private_key": "${PRIVATE_KEY}",
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
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "uuid": "${UUID}",
          "password": "${TUIC_PASSWORD}"
        }
      ],
      "congestion": "bbr",
      "udp_relay_mode": "native",
      "zero_rtt_handshake": false,
      "heartbeat": "10s",
      "tls": {
        "enabled": true,
        "server_name": "${REALITY_DOMAIN}",
        "alpn": [
          "h3"
        ],
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${REALITY_DOMAIN}",
            "server_port": 443
          },
          "private_key": "${PRIVATE_KEY}",
          "short_id": [
            "${SHORT_ID}"
          ]
        }
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
    "rules": [
      {
        "protocol": [
          "dns"
        ],
        "outbound": "dns-out"
      }
    ],
    "auto_detect_interface": true,
    "final": "direct"
  }
}
EOF

  log "配置写入完成，检查 JSON 合法性..."
  if ! sing-box check -c /etc/sing-box/config.json; then
    err "配置检查失败，请手动检查 /etc/sing-box/config.json"
    exit 1
  fi
}

###################################
# 5. systemd 服务
###################################
setup_systemd() {
  log "写入 /etc/systemd/system/sing-box.service ..."
  cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service
After=network.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable sing-box
  systemctl restart sing-box

  sleep 1
  if systemctl is-active --quiet sing-box; then
    log "✅ sing-box 服务启动成功。"
  else
    err "sing-box 服务启动失败，请执行 'journalctl -u sing-box -e' 查看日志。"
    exit 1
  fi
}

###################################
# 6. 生成分享链接 + 二维码
###################################
generate_links_and_qrcode() {
  # 自动获取公网 IP，失败则手动输入
  IPV4=$(curl -4s https://api-ipv4.ip.sb 2>/dev/null || curl -4s ifconfig.me 2>/dev/null || true)
  if [ -z "$IPV4" ]; then
    read -rp "请输入服务器公网 IPv4: " IPV4
  fi

  VLESS_URL="vless://${UUID}@${IPV4}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp#VLESS-REALITY"
  TUIC_URL="tuic://${UUID}:${TUIC_PASSWORD}@${IPV4}:${TUIC_PORT}?congestion=bbr&sni=${REALITY_DOMAIN}&alpn=h3&udp_relay_mode=native&allow_insecure=0#TUIC-REALITY"

  echo
  echo "================= VLESS Reality 链接 ================="
  echo "$VLESS_URL"
  echo "====================================================="
  echo
  echo "================== TUIC Reality 链接 ================="
  echo "$TUIC_URL"
  echo "====================================================="
  echo

  local QR_DIR="/root/singbox-qrcode"
  mkdir -p "$QR_DIR"

  echo "$VLESS_URL" | qrencode -o "${QR_DIR}/vless-reality.png"
  echo "$TUIC_URL"   | qrencode -o "${QR_DIR}/tuic-reality.png"

  log "已生成二维码："
  echo "  VLESS QR: ${QR_DIR}/vless-reality.png"
  echo "  TUIC  QR: ${QR_DIR}/tuic-reality.png"

  log "可以复制上面的链接给朋友，或将二维码发到手机扫。"
}

###################################
# 主流程
###################################
main() {
  check_root
  check_os
  install_deps
  install_sing_box
  choose_reality_domain
  ask_ports_and_params
  prepare_config
  setup_systemd
  generate_links_and_qrcode

  echo
  log "🎉 全部完成！"
  echo "1）安卓 NekoBox / Sing-box：导入 vless:// 或 tuic:// 即可使用"
  echo "2）Mac Surge / Clash / Nekoray：新建节点 → 粘贴链接导入"
  echo "3）后续你可以把 VLESS_URL / TUIC_URL 直接写进 README / X 帖子分享"
}

main "$@"
