#!/usr/bin/env bash
# VLESS-REALITY + TUIC 一键安装脚本（修复版 v3）

set -e

# ========= 通用输出函数 =========
info()  { echo -e "\033[32m[INFO]\033[0m  $*"; }
warn()  { echo -e "\033[33m[WARN]\033[0m  $*"; }
error() { echo -e "\033[31m[ERR ]\033[0m  $*"; }
sep()   { echo -e "\033[36m====================================================\033[0m"; }

CONFIG_DIR="/etc/sing-box"
CONFIG_PATH="${CONFIG_DIR}/config.json"
REALITY_TXT="${CONFIG_DIR}/reality.txt"
SERVICE_FILE="/etc/systemd/system/sing-box.service"
ARCH=""
SINGBOX_BIN="/usr/local/bin/sing-box"

# ========= 检查 root & 系统 =========
check_root() {
  if [[ $EUID -ne 0 ]]; then
    error "请使用 root 用户运行此脚本（sudo -i 再执行）。"
    exit 1
  fi
}

check_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "$ID" in
      ubuntu|debian)
        info "检测到系统: $PRETTY_NAME"
        ;;
      *)
        warn "未在 Ubuntu/Debian 上测试，当前为: $PRETTY_NAME"
        ;;
    esac
  fi
}

# ========= 检测 CPU 架构 =========
detect_arch() {
  local raw_arch
  raw_arch=$(uname -m)
  case "$raw_arch" in
    x86_64|amd64)
      ARCH="amd64"
      ;;
    aarch64|arm64)
      ARCH="arm64"
      ;;
    armv7*|armv6*)
      ARCH="armv7"
      ;;
    *)
      error "不支持的架构: $raw_arch"
      exit 1
      ;;
  esac
  info "检测到架构: $raw_arch ($ARCH)"
}

# ========= 安装依赖 =========
install_deps() {
  info "更新 apt 源并安装依赖（curl jq qrencode openssl）..."
  apt-get update -y
  apt-get install -y curl jq qrencode openssl
}

# ========= 获取 sing-box 最新版本 =========
get_latest_singbox_version() {
  # 使用 GitHub API 获取最新 tag
  local api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
  info "检测并安装最新 sing-box ..."
  local latest_tag
  latest_tag=$(curl -fsSL "$api_url" | jq -r '.tag_name' 2>/dev/null || echo "")
  if [[ -z "$latest_tag" || "$latest_tag" == "null" ]]; then
    # 兜底版本（如果 API 失败）
    latest_tag="v1.12.12"
    warn "获取最新版本失败，将使用兜底版本: $latest_tag"
  fi
  echo "$latest_tag"
}

install_singbox() {
  local latest_tag
  latest_tag=$(get_latest_singbox_version)
  local url="https://github.com/SagerNet/sing-box/releases/download/${latest_tag}/sing-box-${latest_tag#v}-linux-${ARCH}.tar.gz"

  info "下载并安装 sing-box ${latest_tag} (${ARCH}) ..."
  mkdir -p /tmp/singbox-install
  cd /tmp/singbox-install

  if ! curl -fSL "$url" -o singbox.tar.gz; then
    error "下载 sing-box 失败: $url"
    exit 1
  fi

  tar -xzf singbox.tar.gz
  local dir
  dir=$(find . -maxdepth 1 -type d -name "sing-box-*" | head -n 1)
  if [[ ! -d "$dir" ]]; then
    error "解压后未找到 sing-box 目录"
    exit 1
  fi

  install -m 755 "$dir/sing-box" "$SINGBOX_BIN"
  cd /
  rm -rf /tmp/singbox-install

  info "sing-box 安装完成: $SINGBOX_BIN"
}

# ========= 域名延迟测试（从你的 Gist 拉取） =========
test_reality_domains() {
  local GIST_URL="https://gist.githubusercontent.com/cj3343/8d38d603440ea50105319d7c09909faf/raw/47e05fcfdece890d1480f462afadc0baffcbb120/domain-list.txt"
  local domain_list
  domain_list=$(curl -fsSL "$GIST_URL" || true)

  if [[ -z "$domain_list" ]]; then
    warn "从 Gist 获取域名失败，将使用内置域名池..."
    domain_list=$'aws.com\nwhatsapp.com\napple.com\nlpsnmedia.net\nnetflix.com\ngoogle.com\ntesla.com\nspotify.com\nicloud.com\ncloudflare.com'
  fi

  info "开始测试 Reality 目标域名延迟（openssl + 443）..."

  local best_domain=""
  local best_rtt=999999

  # 只测前 20 个域名，避免太久
  local count=0
  while read -r d; do
    [[ -z "$d" ]] && continue
    ((count++))
    if (( count > 20 )); then
      break
    fi

    local t1 t2 rtt
    t1=$(date +%s%3N)
    if timeout 1 openssl s_client -connect "$d:443" -servername "$d" </dev/null &>/dev/null; then
      t2=$(date +%s%3N)
      rtt=$((t2 - t1))
      echo "  $d: ${rtt} ms"
      if (( rtt < best_rtt )); then
        best_rtt=$rtt
        best_domain="$d"
      fi
    else
      echo "  $d: timeout"
    fi
  done <<< "$domain_list"

  if [[ -z "$best_domain" ]]; then
    warn "所有域名测试均失败，将使用默认: www.apple.com"
    best_domain="www.apple.com"
    best_rtt=0
  fi

  info "✅ 选中的最低延迟域名：$best_domain (${best_rtt} ms)"
  echo "$best_domain"
}

ask_reality_domain() {
  local auto_domain
  auto_domain=$(test_reality_domains)

  while true; do
    read -r -p "Reality 伪装域名 [回车使用自动选择: ${auto_domain}]：" input_domain
    input_domain=${input_domain:-$auto_domain}

    # 简单校验：必须包含 .
    if [[ "$input_domain" != *.* ]]; then
      warn "域名格式不正确，请重新输入。"
      continue
    fi

    echo "$input_domain"
    return
  done
}

ask_ports() {
  local vless_port tuic_port
  read -r -p "VLESS Reality 端口 [默认: 443]: " vless_port
  read -r -p "TUIC 端口 [默认: 8443]: " tuic_port

  vless_port=${vless_port:-443}
  tuic_port=${tuic_port:-8443}

  info "✅ VLESS 端口: $vless_port"
  info "✅ TUIC  端口: $tuic_port"

  echo "$vless_port $tuic_port"
}

# ========= 生成 UUID & Reality 密钥 =========
generate_uuid() {
  uuidgen | tr 'A-Z' 'a-z'
}

generate_reality_keypair() {
  mkdir -p "$CONFIG_DIR"
  cd "$CONFIG_DIR"

  # sing-box generate reality-keypair 没有 --json，只能直接解析 stdout
  local output
  output=$($SINGBOX_BIN generate reality-keypair 2>/dev/null)

  # 兼容两种格式：
  # 1) PrivateKey: xxx / PublicKey: yyy
  # 2) { "private_key": "...", "public_key": "..." }
  local pri pub

  if echo "$output" | grep -qi "PrivateKey:"; then
    pri=$(echo "$output" | grep -i "PrivateKey" | awk '{print $2}')
    pub=$(echo "$output" | grep -i "PublicKey"  | awk '{print $2}')
  else
    pri=$(echo "$output" | jq -r '.private_key' 2>/dev/null || true)
    pub=$(echo "$output" | jq -r '.public_key'  2>/dev/null || true)
  fi

  if [[ -z "$pri" || -z "$pub" || "$pri" == "null" || "$pub" == "null" ]]; then
    error "解析 Reality 密钥失败，原始输出："
    echo "$output"
    exit 1
  fi

  echo "PrivateKey: $pri" > "$REALITY_TXT"
  echo "PublicKey:  $pub" >> "$REALITY_TXT"

  info "Reality 密钥已保存到 $REALITY_TXT"

  # 返回给调用者
  echo "$pri|$pub"
}

# ========= 写入 config.json =========
write_config() {
  local uuid="$1"
  local reality_domain="$2"
  local vless_port="$3"
  local tuic_port="$4"
  local reality_pri="$5"
  local reality_sid="$6"

  mkdir -p "$CONFIG_DIR"

  if [[ -f "$CONFIG_PATH" ]]; then
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak-$(date +%s)"
    warn "已备份旧 config.json 为 ${CONFIG_PATH}.bak-时间戳"
  fi

  cat > "$CONFIG_PATH" <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "google",
        "address": "https://dns.google/dns-query"
      },
      {
        "tag": "local",
        "address": "local"
      }
    ]
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": ${vless_port},
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "uuid": "${uuid}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${reality_domain}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${reality_domain}",
            "server_port": 443
          },
          "private_key": "${reality_pri}",
          "short_id": ["${reality_sid}"]
        }
      }
    },
    {
      "type": "tuic",
      "tag": "tuic",
      "listen": "::",
      "listen_port": ${tuic_port},
      "users": [
        {
          "uuid": "${uuid}",
          "password": "${uuid}"
        }
      ],
      "congestion_control": "bbr",
      "zero_rtt_handshake": true,
      "udp_relay_mode": "native",
      "heartbeat": "10s",
      "tls": {
        "enabled": true,
        "server_name": "${reality_domain}",
        "insecure": true,
        "alpn": ["h3"]
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
    "geoip": {
      "download_url": "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db",
      "download_detour": "direct"
    },
    "geosite": {
      "download_url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db",
      "download_detour": "direct"
    },
    "rules": [
      {
        "rule_set": "geosite-category-ads-all",
        "outbound": "block"
      },
      {
        "geoip": [
          "private"
        ],
        "outbound": "direct"
      },
      {
        "geosite": [
          "cn"
        ],
        "geoip": [
          "cn"
        ],
        "outbound": "direct"
      }
    ],
    "rule_set": [
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite-category-ads-all.srs",
        "download_detour": "direct"
      }
    ]
  }
}
EOF

  info "写入 /etc/sing-box/config.json ..."
}

# ========= 写入 systemd service =========
write_service() {
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Sing-box Service
After=network.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=${SINGBOX_BIN} run -c ${CONFIG_PATH}
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable sing-box
}

# ========= 生成分享链接 & 二维码 =========
generate_links_and_qr() {
  local uuid="$1"
  local reality_domain="$2"
  local vless_port="$3"
  local tuic_port="$4"
  local reality_pub="$5"
  local reality_sid="$6"

  # 获取 IPv4
  local ipv4
  ipv4=$(curl -4s https://api-ipv4.ip.sb || curl -4s ifconfig.me || echo "YOUR_IP")

  local vless_url="vless://${uuid}@${ipv4}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${reality_domain}&fp=chrome&pbk=${reality_pub}&sid=${reality_sid}&type=tcp#VLESS-REALITY"
  local tuic_url="tuic://${uuid}:${uuid}@${ipv4}:${tuic_port}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#TUIC-H3"

  sep
  echo "VLESS Reality 链接："
  echo "$vless_url"
  sep
  echo "TUIC 链接："
  echo "$tuic_url"
  sep

  # 生成二维码（放在当前目录）
  qrencode -t ansiutf8 "$vless_url" > /root/vless-reality-qr.txt || true
  qrencode -t ansiutf8 "$tuic_url"  > /root/tuic-qr.txt || true

  echo "已在 /root 生成二维码文本："
  echo "  /root/vless-reality-qr.txt"
  echo "  /root/tuic-qr.txt"
}

# ========= 主流程 =========
main() {
  check_root
  check_os
  detect_arch
  install_deps
  install_singbox

  sep
  info "Reality 伪装域名 & 端口配置"
  sep

  local rd
  rd=$(ask_reality_domain)

  local vp tp
  read vp tp <<<"$(ask_ports)"

  sep
  info "生成 UUID & Reality 密钥对 ..."
  sep

  local uuid
  uuid=$(generate_uuid)

  local keypair reality_pri reality_pub
  keypair=$(generate_reality_keypair)
  reality_pri="${keypair%%|*}"
  reality_pub="${keypair##*|}"

  # 生成随机 short_id（16 个十六进制字符）
  local sid
  sid=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
  [[ -z "$sid" ]] && sid="65d8a7718e29e3cf"

  info "UUID:        $uuid"
  info "Reality Pri: $reality_pri"
  info "Reality Pub: $reality_pub"
  info "Reality SID: $sid"

  sep
  info "写入配置文件 ..."
  sep

  write_config "$uuid" "$rd" "$vp" "$tp" "$reality_pri" "$sid"

  sep
  info "检查配置合法性 ..."
  sep

  if ! $SINGBOX_BIN check -c "$CONFIG_PATH"; then
    error "配置检查失败，请手动修复 $CONFIG_PATH 后重试。"
    exit 1
  fi

  sep
  info "配置通过，写入 systemd 并启动服务 ..."
  sep

  write_service
  systemctl restart sing-box

  sleep 1
  if systemctl is-active --quiet sing-box; then
    info "sing-box 已成功启动。"
  else
    error "sing-box 启动失败，请使用 'journalctl -u sing-box -e' 查看日志。"
    exit 1
  fi

  sep
  info "生成分享链接与二维码 ..."
  sep

  generate_links_and_qr "$uuid" "$rd" "$vp" "$tp" "$reality_pub" "$sid"

  sep
  echo "全部完成！"
  echo "提示："
  echo "1）安卓 NekoBox：直接导入 vless:// 或 tuic:// 即可；"
  echo "2）Mac Surge / sing-box / Nekoray：新建节点 → 粘贴链接导入；"
  echo "3）后续你可以把 VLESS_URL / TUIC_URL 直接发给朋友或写进 README/X 帖子。"
  sep
}

main "$@"
