#!/usr/bin/env bash
# VLESS-REALITY + TUIC 一键安装脚本（修复版 v3）

set -uo pipefail

# ---- 全局证书变量（默认自签名）----
TUIC_CERT_PATH="/etc/sing-box/tuic.crt"
TUIC_KEY_PATH="/etc/sing-box/tuic.key"
TUIC_ALLOW_INSECURE=1
CUSTOM_DOMAIN=""

############## 通用函数 ##############

log()  { echo -e "\033[32m[INFO]\033[0m $*"; }
warn() { echo -e "\033[33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[31m[ERR ]\033[0m $*" >&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    err "缺少命令: $1"
    exit 1
  }
}

############## 清理旧配置 ##############

clean_old_install() {
  log "开始清理旧的 sing-box 配置和数据..."
  
  # 停止服务
  if systemctl is-active --quiet sing-box 2>/dev/null; then
    log "停止 sing-box 服务..."
    systemctl stop sing-box
  fi
  
  # 禁用服务
  if systemctl is-enabled --quiet sing-box 2>/dev/null; then
    log "禁用 sing-box 服务..."
    systemctl disable sing-box
  fi
  
  # 删除服务文件
  if [ -f /etc/systemd/system/sing-box.service ]; then
    log "删除 systemd 服务文件..."
    rm -f /etc/systemd/system/sing-box.service
    systemctl daemon-reload
  fi
  
  # 备份并删除配置目录
  if [ -d /etc/sing-box ]; then
    local backup_name="/root/sing-box-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    log "备份旧配置到: $backup_name"
    tar -czf "$backup_name" /etc/sing-box/ 2>/dev/null || true
    log "删除旧配置目录..."
    rm -rf /etc/sing-box
  fi
  
  # 清理临时文件
  if [ -d /tmp/sb-reality ]; then
    rm -rf /tmp/sb-reality
  fi
  rm -f /tmp/sing-box-config-*.json 2>/dev/null || true
  rm -f /tmp/sb.tar.gz 2>/dev/null || true
  
  log "✅ 清理完成！旧配置已备份到 /root/"
  echo
}

show_menu() {
  echo "========================================"
  echo "   VPN 节点一键安装脚本"
  echo "========================================"
  echo "=== Sing-box 管理 ==="
  echo "1. 全新安装 Sing-box（推荐）"
  echo "2. 清理旧配置后重新安装"
  echo "3. 仅清理配置（不安装）"
  echo "4. 卸载 sing-box"
  echo "5. 查看当前配置"
  echo "6. 诊断连接问题"
  echo "7. 🔥 彻底清理并重装（完全重置）"
  echo "8. 查询 Reality 域名"
  echo "9. 修改 Reality 域名"
  echo "10. 综合检查（安装完整性）"
  echo "11. 重新加载节点信息和二维码"
  echo ""
  echo "=== Snell 管理 ==="
  echo "12. 安装 Snell 节点"
  echo "13. 查看 Snell 配置"
  echo "14. 卸载 Snell"
  echo "15. 重启 Snell 服务"
  echo "16. 重新生成 Snell 配置"
  echo "17. 🔍 诊断 Snell 连接问题"
  echo ""
  echo "18. 配置自有域名 SSL 证书（替换 TUIC 自签名）"
  echo "0. 退出"
  echo "========================================"
  echo
}

deep_clean() {
  warn "⚠️  此操作将："
  echo "  - 停止并删除 sing-box 服务"
  echo "  - 删除所有配置文件（包括备份）"
  echo "  - 删除 sing-box 程序"
  echo "  - 清理所有临时文件"
  echo
  read -rp "确认执行彻底清理？(yes/no): " confirm
  
  if [ "$confirm" != "yes" ]; then
    log "已取消"
    return
  fi
  
  log "开始彻底清理..."
  
  # 停止服务
  systemctl stop sing-box 2>/dev/null || true
  systemctl disable sing-box 2>/dev/null || true
  
  # 删除服务文件
  rm -f /etc/systemd/system/sing-box.service
  systemctl daemon-reload
  
  # 删除程序
  rm -f /usr/local/bin/sing-box
  
  # 完全删除配置目录（不备份）
  rm -rf /etc/sing-box
  
  # 清理临时文件
  rm -rf /tmp/sb-reality
  rm -f /tmp/sing-box-config-*.json 2>/dev/null || true
  rm -f /tmp/sb.tar.gz 2>/dev/null || true
  
  # 清理旧备份
  rm -f /root/sing-box-backup-*.tar.gz 2>/dev/null || true
  rm -f /root/sing-box-final-backup-*.tar.gz 2>/dev/null || true
  
  log "✅ 彻底清理完成！系统已恢复到初始状态"
  echo
}

diagnose_connection() {
  echo "========================================"
  echo "🔍 开始诊断连接问题"
  echo "========================================"
  echo
  
  # 1. 检查服务状态
  log "1. 检查 sing-box 服务状态..."
  if systemctl is-active --quiet sing-box; then
    echo "✅ 服务正在运行"
  else
    err "❌ 服务未运行！"
    echo "尝试启动服务："
    systemctl start sing-box
    sleep 2
    systemctl status sing-box --no-pager -l | head -n 15
  fi
  echo
  
  # 2. 检查端口监听
  log "2. 检查端口监听状态..."
  if command -v ss >/dev/null 2>&1; then
    ss -tulnp | grep sing-box || warn "未找到 sing-box 监听端口"
  else
    netstat -tulnp | grep sing-box || warn "未找到 sing-box 监听端口"
  fi
  echo
  
  # 3. 检查配置文件
  log "3. 检查配置文件..."
  if [ -f /etc/sing-box/config.json ]; then
    echo "✅ 配置文件存在"
    if sing-box check -c /etc/sing-box/config.json 2>&1 | grep -q "configuration valid"; then
      echo "✅ 配置文件语法正确"
    else
      err "❌ 配置文件有问题！"
      sing-box check -c /etc/sing-box/config.json
    fi
  else
    err "❌ 配置文件不存在！"
  fi
  echo
  
  # 4. 检查防火墙
  log "4. 检查防火墙状态..."
  if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
      echo "防火墙已启用，检查端口规则："
      ufw status | grep -E "443|8443"
      if ! ufw status | grep -q "443"; then
        warn "⚠️  443 端口未开放！运行以下命令开放："
        echo "  ufw allow 443/tcp"
      fi
      if ! ufw status | grep -q "8443"; then
        warn "⚠️  8443 端口未开放！运行以下命令开放："
        echo "  ufw allow 8443/udp"
      fi
    else
      echo "防火墙未启用"
    fi
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --list-ports
  else
    echo "未检测到防火墙"
  fi
  echo
  
  # 5. 检查日志错误
  log "5. 查看最近的错误日志..."
  journalctl -u sing-box -n 20 --no-pager | grep -i "error\|fatal\|fail" || echo "未发现明显错误"
  echo
  
  # 6. 测试域名连通性
  log "6. 测试 Reality 伪装域名连通性..."
  if [ -f /etc/sing-box/config.json ]; then
    local domain=$(grep -o '"server_name": *"[^"]*"' /etc/sing-box/config.json | head -n1 | cut -d'"' -f4)
    if [ -n "$domain" ]; then
      echo "测试域名: $domain"
      if timeout 3 openssl s_client -connect "$domain:443" -servername "$domain" </dev/null 2>&1 | grep -q "Verify return code: 0"; then
        echo "✅ 域名 $domain 可正常访问"
      else
        warn "⚠️  域名 $domain 连接有问题"
      fi
    fi
  fi
  echo
  
  # 7. 提供建议
  echo "========================================"
  log "💡 常见问题解决方案："
  echo "========================================"
  echo
  echo "问题1：连接被重置"
  echo "  → 检查客户端配置是否正确（IP、端口、UUID）"
  echo "  → 检查服务器防火墙是否开放端口"
  echo "  → 检查 VPS 提供商的安全组/防火墙规则"
  echo
  echo "问题2：无法连接"
  echo "  → ping 服务器 IP 是否通"
  echo "  → 检查端口是否被 VPS 提供商封禁"
  echo "  → 尝试更换端口（避免使用 80、443、8080 等常见端口）"
  echo
  echo "问题3：可以 ping 通但连不上"
  echo "  → ICMP 和 TCP/UDP 是不同的协议"
  echo "  → 用 telnet 或 nc 测试具体端口"
  echo "  → 检查 Reality 域名是否被墙"
  echo
  echo "问题4：配置正确但还是连不上"
  echo "  → 重启 sing-box 服务：systemctl restart sing-box"
  echo "  → 查看实时日志：journalctl -u sing-box -f"
  echo "  → 尝试更换 Reality 伪装域名"
  echo
  echo "========================================"
  echo
  read -rp "是否查看实时日志？(y/n): " view_logs
  if [[ "$view_logs" =~ ^[Yy]$ ]]; then
    log "显示实时日志（按 Ctrl+C 退出）..."
    sleep 1
    journalctl -u sing-box -f
  fi
}

uninstall_singbox() {
  log "开始卸载 sing-box..."
  
  # 停止并禁用服务
  systemctl stop sing-box 2>/dev/null || true
  systemctl disable sing-box 2>/dev/null || true
  
  # 删除服务文件
  rm -f /etc/systemd/system/sing-box.service
  systemctl daemon-reload
  
  # 备份配置
  if [ -d /etc/sing-box ]; then
    local backup_name="/root/sing-box-final-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$backup_name" /etc/sing-box/ 2>/dev/null || true
    log "配置已备份到: $backup_name"
  fi
  
  # 删除文件
  rm -rf /etc/sing-box
  rm -f /usr/local/bin/sing-box
  rm -rf /tmp/sb-reality
  rm -f /tmp/sing-box-config-*.json 2>/dev/null || true
  
  log "✅ sing-box 已完全卸载！"
  log "配置备份保存在 /root/ 目录下"
}

show_current_config() {
  if [ ! -f /etc/sing-box/config.json ]; then
    warn "未找到配置文件 /etc/sing-box/config.json"
    return
  fi
  
  echo "========================================"
  echo "当前配置信息："
  echo "========================================"
  
  if [ -f /etc/sing-box/share-links.txt ]; then
    cat /etc/sing-box/share-links.txt
  else
    warn "未找到分享链接文件"
  fi
  
  echo
  echo "服务状态："
  systemctl status sing-box --no-pager -l | head -n 10
  echo "========================================"
}

############## 安装基础依赖 ##############

install_base() {
  if command -v apt-get >/dev/null 2>&1; then
    log "检测到 Debian/Ubuntu 系统，安装依赖..."
    apt-get update -y
    apt-get install -y curl wget jq openssl qrencode sudo chrony
    systemctl enable chrony --now >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    log "检测到 CentOS/RHEL 系统，安装依赖..."
    yum install -y epel-release
    yum install -y curl wget jq openssl qrencode sudo chrony
    systemctl enable chronyd --now >/dev/null 2>&1 || true
  else
    err "无法识别的系统（非 apt / yum），请手动安装 curl、wget、jq、openssl。"
    exit 1
  fi
}

############## 安装前检查与优化 ##############

check_prereqs() {
  local missing=0
  for cmd in jq curl wget sudo; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      warn "缺少命令: $cmd"
      missing=1
    fi
  done

  if systemctl is-active --quiet chrony 2>/dev/null; then
    log "chrony 服务已运行"
  elif systemctl is-active --quiet chronyd 2>/dev/null; then
    log "chronyd 服务已运行"
  else
    warn "chrony/chronyd 未运行"
  fi

  if [ "$missing" -eq 1 ]; then
    warn "前置依赖未完整安装，建议重新运行依赖安装步骤"
  else
    log "前置依赖检查通过"
  fi

  log "当前系统时间：$(date)"
}

enable_bbr() {
  if ! sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
    log "尝试启用 BBR 加速..."
    modprobe tcp_bbr >/dev/null 2>&1 || true
    cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl --system >/dev/null 2>&1 || true
  fi

  if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
    log "✅ BBR 已启用"
  else
    warn "⚠️  BBR 未启用（可能内核不支持）"
  fi
}

############## 综合检查 ##############

full_health_check() {
  echo "========================================"
  echo "🧪 综合检查（安装完整性）"
  echo "========================================"

  check_prereqs

  if command -v sing-box >/dev/null 2>&1; then
    log "sing-box 版本：$(sing-box version 2>/dev/null || echo '未知')"
  else
    warn "未找到 sing-box 可执行文件"
  fi

  if [ -f /etc/sing-box/config.json ]; then
    log "配置文件存在：/etc/sing-box/config.json"
    if sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1; then
      log "配置检查通过"
    else
      err "配置检查失败"
    fi
  else
    warn "未找到配置文件 /etc/sing-box/config.json"
  fi

  if command -v jq >/dev/null 2>&1 && [ -f /etc/sing-box/config.json ]; then
    local vless_port tuic_port reality_domain
    vless_port=$(jq -r '.inbounds[] | select(.type=="vless" and .tag=="vless-reality") | .listen_port' /etc/sing-box/config.json 2>/dev/null | head -n 1)
    tuic_port=$(jq -r '.inbounds[] | select(.type=="tuic" and .tag=="tuic") | .listen_port' /etc/sing-box/config.json 2>/dev/null | head -n 1)
    reality_domain=$(jq -r '.inbounds[] | select(.type=="vless" and .tag=="vless-reality") | .tls.server_name' /etc/sing-box/config.json 2>/dev/null | head -n 1)
    [ -n "$vless_port" ] && log "VLESS 端口: $vless_port"
    [ -n "$tuic_port" ] && log "TUIC  端口: $tuic_port"
    [ -n "$reality_domain" ] && log "Reality 域名: $reality_domain"

    if command -v ss >/dev/null 2>&1; then
      [ -n "$vless_port" ] && ss -tulnp | grep -q ":${vless_port} " && log "VLESS 端口监听正常" || warn "VLESS 端口未监听"
      [ -n "$tuic_port" ] && ss -tulnp | grep -q ":${tuic_port} " && log "TUIC  端口监听正常" || warn "TUIC  端口未监听"
    elif command -v netstat >/dev/null 2>&1; then
      [ -n "$vless_port" ] && netstat -tulnp | grep -q ":${vless_port} " && log "VLESS 端口监听正常" || warn "VLESS 端口未监听"
      [ -n "$tuic_port" ] && netstat -tulnp | grep -q ":${tuic_port} " && log "TUIC  端口监听正常" || warn "TUIC  端口未监听"
    else
      warn "未找到 ss/netstat，跳过端口监听检查"
    fi
  fi

  if systemctl is-active --quiet sing-box 2>/dev/null; then
    log "sing-box 服务运行中"
  else
    warn "sing-box 服务未运行"
  fi

  if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
    log "BBR 已启用"
  else
    warn "BBR 未启用"
  fi

  echo "========================================"
}

reload_share_links() {
  if [ ! -f /etc/sing-box/config.json ]; then
    warn "未找到配置文件 /etc/sing-box/config.json"
    return
  fi
  if ! command -v jq >/dev/null 2>&1; then
    err "缺少命令: jq"
    return
  fi

  local vless_port vless_uuid tuic_port tuic_uuid tuic_pass
  vless_port=$(jq -r '.inbounds[] | select(.type=="vless" and .tag=="vless-reality") | .listen_port' /etc/sing-box/config.json 2>/dev/null | head -n 1)
  vless_uuid=$(jq -r '.inbounds[] | select(.type=="vless" and .tag=="vless-reality") | .users[0].uuid' /etc/sing-box/config.json 2>/dev/null | head -n 1)
  tuic_port=$(jq -r '.inbounds[] | select(.type=="tuic" and .tag=="tuic") | .listen_port' /etc/sing-box/config.json 2>/dev/null | head -n 1)
  tuic_uuid=$(jq -r '.inbounds[] | select(.type=="tuic" and .tag=="tuic") | .users[0].uuid' /etc/sing-box/config.json 2>/dev/null | head -n 1)
  tuic_pass=$(jq -r '.inbounds[] | select(.type=="tuic" and .tag=="tuic") | .users[0].password' /etc/sing-box/config.json 2>/dev/null | head -n 1)
  REALITY_DOMAIN=$(jq -r '.inbounds[] | select(.type=="vless" and .tag=="vless-reality") | .tls.server_name' /etc/sing-box/config.json 2>/dev/null | head -n 1)
  SHORT_ID=$(jq -r '.inbounds[] | select(.type=="vless" and .tag=="vless-reality") | .tls.reality.short_id[0]' /etc/sing-box/config.json 2>/dev/null | head -n 1)

  if [ -f /etc/sing-box/reality.txt ]; then
    REALITY_PUBLIC=$(grep -i "PublicKey" /etc/sing-box/reality.txt | awk '{print $2}')
  fi

  if [ -z "${REALITY_PUBLIC:-}" ]; then
    read -rp "未找到 Reality 公钥，请手动输入： " REALITY_PUBLIC
  fi

  if [ -z "$vless_port" ] || [ -z "$vless_uuid" ] || [ -z "$tuic_port" ] || [ -z "$tuic_uuid" ] || [ -z "$tuic_pass" ] || [ -z "$REALITY_DOMAIN" ] || [ -z "$REALITY_PUBLIC" ] || [ -z "$SHORT_ID" ]; then
    err "读取配置不完整，无法重新生成节点信息"
    return
  fi

  gen_share_links "$vless_port" "$tuic_port" "$vless_uuid" "$tuic_uuid" "$tuic_pass"
}

############## Snell 安装与管理 ##############

check_snell_dependencies() {
  local missing=0
  for cmd in wget unzip; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      warn "缺少命令: $cmd"
      missing=1
    fi
  done

  if [ "$missing" -eq 1 ]; then
    log "安装缺失的依赖..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y && apt-get install -y wget unzip
    elif command -v yum >/dev/null 2>&1; then
      yum install -y wget unzip
    else
      err "无法自动安装依赖，请手动安装 wget 和 unzip"
      return 1
    fi
  fi
  return 0
}

install_snell() {
  log "开始安装 Snell 节点..."

  # 检查依赖
  check_snell_dependencies || return 1

  # 检测系统架构
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64) SNELL_ARCH="amd64" ;;
    aarch64|arm64) SNELL_ARCH="aarch64" ;;
    *)
      err "不支持的 CPU 架构: $ARCH"
      return 1
      ;;
  esac

  # Snell 版本（使用最新稳定版）
  SNELL_VERSION="v4.1.1"
  SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-${SNELL_ARCH}.zip"

  log "下载 Snell ${SNELL_VERSION} (${SNELL_ARCH})..."
  cd /tmp

  # 清理旧文件
  rm -f snell.zip snell-server

  # 下载并验证
  if ! wget --no-check-certificate -O snell.zip "$SNELL_URL"; then
    err "下载失败，尝试使用备用源..."
    # 备用下载源
    SNELL_BACKUP_URL="https://raw.githubusercontent.com/xOS/Others/master/snell/v4/snell-server-${SNELL_VERSION}-linux-${SNELL_ARCH}.zip"
    if ! wget --no-check-certificate -O snell.zip "$SNELL_BACKUP_URL"; then
      err "所有下载源均失败，请检查网络连接"
      return 1
    fi
  fi

  # 验证文件大小
  if [ ! -s snell.zip ]; then
    err "下载的文件为空"
    return 1
  fi

  # 解压
  if ! unzip -o snell.zip; then
    err "解压失败，文件可能损坏"
    rm -f snell.zip
    return 1
  fi

  # 验证可执行文件
  if [ ! -f snell-server ]; then
    err "未找到 snell-server 可执行文件"
    return 1
  fi

  # 安装到系统目录
  chmod +x snell-server
  mv -f snell-server /usr/local/bin/snell-server
  rm -f snell.zip

  log "✅ Snell 二进制文件已安装: /usr/local/bin/snell-server"

  # 生成随机端口和 PSK
  SNELL_PORT=$(shuf -i 30000-65000 -n 1)
  SNELL_PSK=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)

  echo
  read -rp "Snell 端口 [默认: ${SNELL_PORT}]：" input_port
  SNELL_PORT=${input_port:-$SNELL_PORT}

  # 创建配置目录
  mkdir -p /etc/snell

  # 生成配置文件
  cat > /etc/snell/snell-server.conf <<EOF
[snell-server]
listen = ::0:${SNELL_PORT}
psk = ${SNELL_PSK}
ipv6 = true
EOF

  # 保存版本信息
  echo "${SNELL_VERSION}" > /etc/snell/ver.txt

  log "配置文件已生成: /etc/snell/snell-server.conf"

  # 创建 systemd 服务（使用 root 运行，参考 xOS 实现）
  cat > /etc/systemd/system/snell.service <<EOF
[Unit]
Description=Snell Proxy Service
After=network.target

[Service]
Type=simple
User=root
LimitNOFILE=32767
ExecStart=/usr/local/bin/snell-server -c /etc/snell/snell-server.conf
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snell-server
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snell-server
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

  # 启动服务
  systemctl daemon-reload
  systemctl enable snell
  systemctl start snell

  sleep 2

  if systemctl is-active --quiet snell; then
    log "✅ Snell 服务启动成功"
  else
    err "❌ Snell 服务启动失败"
    systemctl status snell --no-pager -l | head -n 15
    return 1
  fi

  # 配置防火墙
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${SNELL_PORT}/tcp" 2>/dev/null || true
    log "防火墙已开放端口 ${SNELL_PORT}/tcp"
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${SNELL_PORT}/tcp"
    firewall-cmd --reload
    log "防火墙已开放端口 ${SNELL_PORT}/tcp"
  fi

  # 生成分享配置
  gen_snell_config "$SNELL_PORT" "$SNELL_PSK"

  log "🎉 Snell 安装完成！"
}

gen_snell_config() {
  local PORT="$1"
  local PSK="$2"

  echo
  local SERVER_IP
  read -rp "服务器公网 IP [回车自动检测]：" SERVER_IP
  if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(detect_ipv4)
  fi

  if [ -z "$SERVER_IP" ]; then
    err "自动检测 IP 失败"
    return
  fi

  # 获取国家代码或使用服务器名称
  local COUNTRY
  COUNTRY=$(curl -s https://ipinfo.io/country 2>/dev/null || echo "VPS")

  # 生成 Surge 格式配置（完整参数）
  local SURGE_CONFIG="${COUNTRY} = snell, ${SERVER_IP}, ${PORT}, psk=${PSK}, version=4, tfo=true, reuse=true, ecn=true"

  # 保存配置
  cat > /etc/snell/config.txt <<EOF
=== Snell 节点配置 ===

服务器: ${SERVER_IP}
端口: ${PORT}
PSK: ${PSK}
版本: 4

=== Surge 配置（直接复制使用）===
${SURGE_CONFIG}

=== 参数说明 ===
- tfo=true: 启用 TCP Fast Open（提升连接速度）
- reuse=true: 启用连接复用（减少延迟）
- ecn=true: 启用 ECN（显式拥塞通知）

=== Shadowrocket 手动配置 ===
1. 打开 Shadowrocket
2. 添加节点 -> 类型选择 Snell
3. 填入以下信息：
   - 地址: ${SERVER_IP}
   - 端口: ${PORT}
   - PSK: ${PSK}
   - 混淆: 无
   - 版本: 4
   - 复用: 开启
   - TCP Fast Open: 开启
EOF

  echo
  echo "================= Snell 节点配置 ================="
  cat /etc/snell/config.txt
  echo "=================================================="
  echo
  log "配置已保存到: /etc/snell/config.txt"
  echo
  log "💡 提示：直接复制上面的 Surge 配置行到 Surge 配置文件即可使用"
}

show_snell_config() {
  if [ ! -f /etc/snell/config.txt ]; then
    warn "未找到 Snell 配置文件，请先安装 Snell"
    return
  fi

  echo "========================================"
  cat /etc/snell/config.txt
  echo "========================================"
  echo
  echo "服务状态："
  systemctl status snell --no-pager -l | head -n 10
}

uninstall_snell() {
  log "开始卸载 Snell..."

  # 停止并禁用服务
  systemctl stop snell 2>/dev/null || true
  systemctl disable snell 2>/dev/null || true

  # 删除服务文件
  rm -f /etc/systemd/system/snell.service
  systemctl daemon-reload

  # 备份配置
  if [ -d /etc/snell ]; then
    local backup_name="/root/snell-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$backup_name" /etc/snell/ 2>/dev/null || true
    log "配置已备份到: $backup_name"
  fi

  # 删除文件
  rm -rf /etc/snell
  rm -f /usr/local/bin/snell-server

  # 删除用户
  if id -u snell >/dev/null 2>&1; then
    userdel snell 2>/dev/null || true
  fi

  log "✅ Snell 已完全卸载！"
}

restart_snell() {
  if ! systemctl is-enabled --quiet snell 2>/dev/null; then
    warn "Snell 服务未安装"
    return
  fi

  log "重启 Snell 服务..."
  systemctl restart snell
  sleep 2
  systemctl status snell --no-pager -l | head -n 10
}

regenerate_snell_config() {
  if [ ! -f /etc/snell/snell-server.conf ]; then
    warn "未找到 Snell 配置文件，请先安装 Snell"
    return
  fi

  log "读取当前配置..."

  # 从配置文件读取端口和 PSK
  local PORT PSK
  PORT=$(grep -oP 'listen = [^:]+:\K\d+' /etc/snell/snell-server.conf 2>/dev/null)
  PSK=$(grep -oP 'psk = \K.*' /etc/snell/snell-server.conf 2>/dev/null)

  if [ -z "$PORT" ] || [ -z "$PSK" ]; then
    err "无法读取配置信息"
    return
  fi

  log "当前端口: $PORT"
  log "当前 PSK: $PSK"
  echo

  # 重新生成配置
  gen_snell_config "$PORT" "$PSK"
}

diagnose_snell() {
  echo "=========================================="
  echo "🔍 Snell 节点诊断"
  echo "=========================================="
  echo

  # 1. 检查服务状态
  log "1. 检查服务状态..."
  if systemctl is-active --quiet snell; then
    echo "✅ 服务正在运行"
    systemctl status snell --no-pager -l | head -n 10
  else
    err "❌ 服务未运行"
    systemctl status snell --no-pager -l | head -n 15
    return
  fi
  echo

  # 2. 检查配置文件
  log "2. 检查配置文件..."
  if [ -f /etc/snell/snell-server.conf ]; then
    echo "✅ 配置文件存在"
    cat /etc/snell/snell-server.conf
  else
    err "❌ 配置文件不存在"
    return
  fi
  echo

  # 3. 检查端口监听
  log "3. 检查端口监听..."
  local PORT
  PORT=$(grep -oP 'listen = [^:]+:\K\d+' /etc/snell/snell-server.conf 2>/dev/null)
  if [ -n "$PORT" ]; then
    echo "配置端口: $PORT"
    if ss -tulnp 2>/dev/null | grep -q ":${PORT} " || netstat -tulnp 2>/dev/null | grep -q ":${PORT} "; then
      echo "✅ 端口 $PORT 正在监听"
      ss -tulnp 2>/dev/null | grep ":${PORT} " || netstat -tulnp 2>/dev/null | grep ":${PORT} "
    else
      err "❌ 端口 $PORT 未监听！"
    fi
  else
    err "❌ 无法读取端口配置"
  fi
  echo

  # 4. 检查防火墙
  log "4. 检查防火墙..."
  if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
      echo "防火墙状态："
      ufw status | grep -E "$PORT|Status"
      if ! ufw status | grep -q "$PORT"; then
        warn "⚠️  端口 $PORT 未在防火墙中开放！"
        echo "运行以下命令开放端口："
        echo "  ufw allow $PORT/tcp"
      fi
    else
      echo "防火墙未启用"
    fi
  elif command -v firewall-cmd >/dev/null 2>&1; then
    echo "firewalld 开放端口："
    firewall-cmd --list-ports
  else
    echo "未检测到防火墙"
  fi
  echo

  # 5. 检查服务日志
  log "5. 检查服务日志（最近20行）..."
  journalctl -u snell -n 20 --no-pager
  echo

  # 6. 本地连接测试
  log "6. 本地连接测试..."
  if [ -n "$PORT" ]; then
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
      echo "✅ 本地端口 $PORT 可连接"
    else
      err "❌ 本地端口 $PORT 无法连接"
    fi
  fi
  echo

  # 7. 公网 IP
  log "7. 服务器公网 IP..."
  local PUBLIC_IP
  PUBLIC_IP=$(detect_ipv4)
  if [ -n "$PUBLIC_IP" ]; then
    echo "公网 IP: $PUBLIC_IP"
  else
    warn "无法获取公网 IP"
  fi
  echo

  # 8. Surge 配置
  log "8. Surge 配置..."
  if [ -f /etc/snell/config.txt ]; then
    grep "snell," /etc/snell/config.txt | head -n 1
  else
    warn "未找到配置文件"
  fi
  echo

  # 9. 总结建议
  echo "=========================================="
  log "💡 排查建议："
  echo "=========================================="
  echo
  echo "问题1：端口未监听"
  echo "  → 检查上面的服务日志，查看启动错误"
  echo "  → 尝试重启服务：systemctl restart snell"
  echo
  echo "问题2：防火墙未开放"
  echo "  → 运行：ufw allow $PORT/tcp"
  echo "  → 或：firewall-cmd --permanent --add-port=$PORT/tcp && firewall-cmd --reload"
  echo
  echo "问题3：云服务商安全组"
  echo "  → 登录 AWS/阿里云/腾讯云控制台"
  echo "  → 在安全组规则中添加入站规则：TCP $PORT"
  echo
  echo "问题4：Surge 配置格式"
  echo "  → 确保使用上面显示的完整配置行"
  echo "  → 格式：name = snell, IP, PORT, psk=xxx, version=4, tfo=true, reuse=true, ecn=true"
  echo "  → 注意：参数之间没有空格（psk=xxx 而不是 psk = xxx）"
  echo
  echo "问题5：Surge 客户端"
  echo "  → 确保 Surge 版本支持 Snell v4"
  echo "  → 尝试在 Surge 中测试延迟"
  echo "  → 查看 Surge 日志是否有错误信息"
  echo
  echo "问题6：网络封锁"
  echo "  → 某些 VPS 提供商可能封禁代理流量"
  echo "  → 尝试更换端口（避免常见端口如 443、8080）"
  echo "  → 考虑使用其他协议（如 sing-box 的 Reality）"
  echo
  echo "=========================================="
}

############## 安装最新 sing-box ##############

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

  # 用 GitHub API 获取最新 tag
  local LATEST_TAG
  LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r '.tag_name')
  if [ -z "$LATEST_TAG" ] || [ "$LATEST_TAG" = "null" ]; then
    err "获取 sing-box 最新版本号失败，请稍后重试。"
    exit 1
  fi

  local VER
  VER="${LATEST_TAG#v}"

  local SB_URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${VER}-linux-${SB_ARCH}.tar.gz"
  log "下载并安装 sing-box ${LATEST_TAG} (${SB_ARCH}) ..."
  cd /tmp
  wget -O sb.tar.gz "$SB_URL"
  tar -xzf sb.tar.gz

  local SB_DIR
  SB_DIR=$(tar -tzf sb.tar.gz | head -n 1 | cut -d/ -f1)
  install -m 755 "${SB_DIR}/sing-box" /usr/local/bin/sing-box

  rm -rf "${SB_DIR}" sb.tar.gz

  log "sing-box 安装完成: $(sing-box version)"
}

############## Reality 域名测试与选择 ##############

GIST_URL="https://gist.githubusercontent.com/cj3343/8d38d603440ea50105319d7c09909faf/raw/47e05fcfdece890d1480f462afadc0baffcbb120/domain-list.txt"

download_domain_list() {
  mkdir -p /tmp/sb-reality
  local FILE="/tmp/sb-reality/domain-list.txt"

  if curl -fsSL "$GIST_URL" -o "$FILE"; then
    log "已从 Gist 拉取 Reality 域名池：$FILE"
  else
    warn "从 Gist 拉取域名池失败，使用内置备用列表。"
    cat > "$FILE" <<EOF
apple.com
www.apple.com
nvidia.com
www.nvidia.com
www.microsoft.com
www.spotify.com
www.tesla.com
s3.amazonaws.com
awsstatic.com
www.whatsapp.com
www.netflix.com
www.google.com
www.cloudflare.com
EOF
  fi
}

test_domains_latency() {
  local FILE="/tmp/sb-reality/domain-list.txt"
  [ -f "$FILE" ] || download_domain_list

  log "开始测试 Reality 目标域名延迟（openssl + 443）..."

  local best_domain=""
  local best_ms=999999

  while read -r d; do
    [ -z "$d" ] && continue
    local t1 t2 cost
    t1=$(date +%s%3N)
    if timeout 1 openssl s_client -connect "$d:443" -servername "$d" </dev/null >/dev/null 2>&1; then
      t2=$(date +%s%3N)
      cost=$((t2 - t1))
      printf "  %-30s %4s ms\n" "$d" "$cost"
      if [ "$cost" -lt "$best_ms" ]; then
        best_ms="$cost"
        best_domain="$d"
      fi
    else
      printf "  %-30s timeout\n" "$d"
    fi
  done < <(shuf "$FILE" | head -n 12)

  if [ -z "$best_domain" ]; then
    warn "所有测试域名均超时，请手动输入一个能 443 访问的大站域名。"
  else
    log "✅ 当前测速最优域名：$best_domain (${best_ms} ms)"
  fi

  REALITY_BEST_DOMAIN="$best_domain"
  REALITY_BEST_MS="$best_ms"
}

choose_reality_domain() {
  download_domain_list
  test_domains_latency

  while true; do
    if [ -n "${REALITY_BEST_DOMAIN:-}" ]; then
      echo
      echo "[INFO] 当前测速最优：${REALITY_BEST_DOMAIN} (${REALITY_BEST_MS} ms)"
      read -rp "Reality 伪装域名 [回车用当前最优 / 输入 r 重新测速 / 输入自定义域名]：" input
      case "$input" in
        "")
          REALITY_DOMAIN="$REALITY_BEST_DOMAIN"
          break
          ;;
        r|R)
          test_domains_latency
          ;;
        *)
          REALITY_DOMAIN="$input"
          break
          ;;
      esac
    else
      read -rp "Reality 伪装域名（例如 www.apple.com / nvidia.com）：" input
      if [ -n "$input" ]; then
        REALITY_DOMAIN="$input"
        break
      fi
    fi
  done

  log "✅ 最终使用的 Reality 伪装域名：$REALITY_DOMAIN"
}

get_current_reality_domain() {
  if ! command -v jq >/dev/null 2>&1; then
    return
  fi
  jq -r '.inbounds[] | select(.type=="vless" and .tag=="vless-reality") | .tls.server_name' /etc/sing-box/config.json 2>/dev/null | head -n 1
}

query_reality_domain() {
  if [ ! -f /etc/sing-box/config.json ]; then
    warn "未找到配置文件 /etc/sing-box/config.json"
    return
  fi
  if ! command -v jq >/dev/null 2>&1; then
    err "缺少命令: jq"
    return
  fi

  local server_name handshake_name link_sni
  server_name=$(get_current_reality_domain)
  handshake_name=$(jq -r '.inbounds[] | select(.type=="vless" and .tag=="vless-reality") | .tls.reality.handshake.server' /etc/sing-box/config.json 2>/dev/null | head -n 1)

  echo "========================================"
  echo "Reality 域名信息："
  echo "========================================"
  echo "server_name: ${server_name:-未找到}"
  echo "handshake.server: ${handshake_name:-未找到}"

  if [ -f /etc/sing-box/share-links.txt ]; then
    link_sni=$(grep -o 'sni=[^&]*' /etc/sing-box/share-links.txt | head -n 1 | cut -d= -f2)
    if [ -n "$link_sni" ]; then
      echo "分享链接 sni: $link_sni"
    fi
  fi
  echo "========================================"
}

update_share_links_reality() {
  local new_domain="$1"
  if [ ! -f /etc/sing-box/share-links.txt ]; then
    warn "未找到分享链接文件 /etc/sing-box/share-links.txt，已跳过更新"
    return
  fi

  local tmp="/tmp/sing-box-share-links-$$.txt"
  sed -E "s/(sni=)[^& ]+/\\1${new_domain}/g" /etc/sing-box/share-links.txt > "$tmp"
  mv "$tmp" /etc/sing-box/share-links.txt
  log "分享链接已更新 sni 参数"
}

update_reality_domain() {
  if [ ! -f /etc/sing-box/config.json ]; then
    warn "未找到配置文件 /etc/sing-box/config.json"
    return
  fi
  if ! command -v jq >/dev/null 2>&1; then
    err "缺少命令: jq"
    return
  fi

  local current_domain
  current_domain=$(get_current_reality_domain)
  log "当前 Reality 域名：${current_domain:-未知}"
  echo
  read -rp "是否自动测速选择新域名？(y/n): " auto_pick
  if [[ "$auto_pick" =~ ^[Yy]$ ]]; then
    choose_reality_domain
  else
    read -rp "输入新的 Reality 域名：" REALITY_DOMAIN
  fi

  if [ -z "${REALITY_DOMAIN:-}" ]; then
    warn "未输入有效域名，已取消修改"
    return
  fi

  local tmp="/tmp/sing-box-config-reality-$$.json"
  if ! jq --arg domain "$REALITY_DOMAIN" \
    '(.inbounds[] | select(.type=="vless" and .tag=="vless-reality") | .tls.server_name) = $domain
     | (.inbounds[] | select(.type=="vless" and .tag=="vless-reality") | .tls.reality.handshake.server) = $domain' \
    /etc/sing-box/config.json > "$tmp"; then
    err "更新配置失败，请检查配置文件格式"
    rm -f "$tmp"
    return
  fi

  if ! sing-box check -c "$tmp"; then
    err "配置检查失败，已保留临时文件: $tmp"
    return
  fi

  cp /etc/sing-box/config.json "/etc/sing-box/config.json.bak-$(date +%s)"
  mv "$tmp" /etc/sing-box/config.json
  log "Reality 域名已更新为：$REALITY_DOMAIN"

  update_share_links_reality "$REALITY_DOMAIN"
  systemctl restart sing-box
  log "sing-box 服务已重启"
}

############## 生成 Reality 密钥 / UUID 等 ##############

generate_reality_keys() {
  mkdir -p /etc/sing-box
  cd /etc/sing-box

  log "生成 Reality 密钥对..."
  sing-box generate reality-keypair > /etc/sing-box/reality.txt

  REALITY_PRIVATE=$(grep -i "PrivateKey" /etc/sing-box/reality.txt | awk '{print $2}')
  REALITY_PUBLIC=$(grep -i "PublicKey"  /etc/sing-box/reality.txt | awk '{print $2}')

  if [ -z "$REALITY_PRIVATE" ] || [ -z "$REALITY_PUBLIC" ]; then
    err "解析 Reality 密钥失败，请检查 /etc/sing-box/reality.txt"
    exit 1
  fi

  SHORT_ID=$(tr -dc 'a-f0-9' </dev/urandom | head -c 16)

  log "Reality 私钥: $REALITY_PRIVATE"
  log "Reality 公钥: $REALITY_PUBLIC"
  log "Reality Short ID: $SHORT_ID"
}

generate_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  else
    cat /proc/sys/kernel/random/uuid
  fi
}

############## 生成 TUIC 自签名证书 ##############

generate_self_signed_cert() {
  log "生成 TUIC 自签名证书..."

  mkdir -p /etc/sing-box
  cd /etc/sing-box

  # 生成自签名证书（10年有效期）
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout tuic.key -out tuic.crt \
    -subj "/CN=tuic.local" \
    -addext "subjectAltName=DNS:tuic.local,DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

  if [ ! -f /etc/sing-box/tuic.key ] || [ ! -f /etc/sing-box/tuic.crt ]; then
    err "生成自签名证书失败！"
    exit 1
  fi

  # 设置权限
  chmod 600 /etc/sing-box/tuic.key
  chmod 644 /etc/sing-box/tuic.crt

  log "✅ TUIC 自签名证书已生成"
  log "  证书: /etc/sing-box/tuic.crt"
  log "  密钥: /etc/sing-box/tuic.key"
}

############## 自有域名 + ACME 证书 ##############

check_domain_dns() {
  local domain="$1"
  local server_ip
  server_ip=$(detect_ipv4)

  local resolved_ip
  resolved_ip=$(getent hosts "$domain" 2>/dev/null | awk '{print $1}' | head -n1)
  if [ -z "$resolved_ip" ]; then
    resolved_ip=$(dig +short "$domain" A 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
  fi

  if [ -z "$resolved_ip" ]; then
    warn "无法解析域名 $domain，请确认 DNS 已正确设置"
    return 1
  fi

  if [ "$resolved_ip" != "$server_ip" ]; then
    warn "域名 $domain 解析到 $resolved_ip，服务器 IP 是 $server_ip"
    warn "DNS 未指向本机，证书申请可能失败"
    return 1
  fi

  log "✅ DNS 解析正常：$domain → $resolved_ip"
  return 0
}

install_acme_sh() {
  if [ -f "$HOME/.acme.sh/acme.sh" ]; then
    log "acme.sh 已安装，跳过"
    return 0
  fi
  log "安装 acme.sh..."
  if ! curl -fsSL https://get.acme.sh | sh -s email=acme@local.invalid; then
    err "acme.sh 安装失败，请检查网络"
    return 1
  fi
  # shellcheck source=/dev/null
  source "$HOME/.acme.sh/acme.sh.env" 2>/dev/null || true
  log "✅ acme.sh 安装完成"
}

obtain_cert_acme() {
  local domain="$1"
  local acme_bin="$HOME/.acme.sh/acme.sh"

  if [ ! -x "$acme_bin" ]; then
    err "acme.sh 未找到，无法申请证书"
    return 1
  fi

  log "申请 Let's Encrypt 证书（域名: $domain，使用 standalone 模式，需要 80 端口空闲）..."

  # 检查 80 端口是否占用
  if ss -tlnp 2>/dev/null | grep -q ':80 '; then
    warn "⚠️  80 端口已被占用，申请可能失败。请确保无其他 HTTP 服务运行在 80 端口"
  fi

  local cert_dir="/etc/sing-box"
  mkdir -p "$cert_dir"

  if "$acme_bin" --issue -d "$domain" \
      --standalone --httpport 80 \
      --fullchain-file "${cert_dir}/tuic-fullchain.crt" \
      --cert-file     "${cert_dir}/tuic.crt" \
      --key-file      "${cert_dir}/tuic.key" \
      --reloadcmd     "systemctl restart sing-box 2>/dev/null || true" \
      2>&1; then

    chmod 600 "${cert_dir}/tuic.key"
    chmod 644 "${cert_dir}/tuic-fullchain.crt" "${cert_dir}/tuic.crt"

    TUIC_CERT_PATH="${cert_dir}/tuic-fullchain.crt"
    TUIC_KEY_PATH="${cert_dir}/tuic.key"
    TUIC_ALLOW_INSECURE=0
    log "✅ 证书申请成功，TUIC 将使用可信证书（allow_insecure=0）"
    log "证书路径: $TUIC_CERT_PATH"
    log "私钥路径: $TUIC_KEY_PATH"
    return 0
  else
    err "证书申请失败，回退到自签名证书"
    TUIC_ALLOW_INSECURE=1
    return 1
  fi
}

setup_custom_domain() {
  echo
  read -rp "您是否有自己的域名并希望用于 TUIC TLS 证书？(y/n): " has_domain
  [[ ! "$has_domain" =~ ^[Yy]$ ]] && return

  read -rp "请输入域名（例如 vpn.example.com）: " input_domain
  if [ -z "$input_domain" ]; then
    warn "未输入域名，跳过"
    return
  fi
  CUSTOM_DOMAIN="$input_domain"

  log "检查域名 DNS 解析..."
  if ! check_domain_dns "$CUSTOM_DOMAIN"; then
    read -rp "DNS 检查未通过，是否仍要尝试申请证书？(y/n): " force_try
    [[ ! "$force_try" =~ ^[Yy]$ ]] && return
  fi

  install_acme_sh || return
  obtain_cert_acme "$CUSTOM_DOMAIN" || true
}

configure_custom_domain_cert() {
  if [ ! -f /etc/sing-box/config.json ]; then
    warn "未找到配置文件 /etc/sing-box/config.json，请先完成安装"
    return
  fi

  setup_custom_domain

  if [ "$TUIC_ALLOW_INSECURE" -eq 0 ]; then
    # 更新 config.json 中的证书路径
    local tmp="/tmp/sing-box-cert-update-$$.json"
    if jq --arg cert "$TUIC_CERT_PATH" --arg key "$TUIC_KEY_PATH" \
      '(.inbounds[] | select(.type=="tuic") | .tls.certificate_path) = $cert
       | (.inbounds[] | select(.type=="tuic") | .tls.key_path) = $key' \
      /etc/sing-box/config.json > "$tmp" && sing-box check -c "$tmp" >/dev/null 2>&1; then
      cp /etc/sing-box/config.json "/etc/sing-box/config.json.bak-$(date +%s)"
      mv "$tmp" /etc/sing-box/config.json
      systemctl restart sing-box
      log "✅ 证书已更新到配置，sing-box 已重启"
    else
      err "配置更新失败，已保留临时文件: $tmp"
    fi

    # 更新分享链接中的 allow_insecure
    if [ -f /etc/sing-box/share-links.txt ]; then
      sed -i 's/allow_insecure=1/allow_insecure=0/g' /etc/sing-box/share-links.txt
      log "分享链接已更新 allow_insecure=0"
    fi
  fi
}

############## 写入 sing-box 配置（完全重写，符合最新格式）##############

write_config() {
  local VLESS_PORT="$1"
  local TUIC_PORT="$2"
  local VLESS_UUID="$3"
  local TUIC_UUID="$4"
  local TUIC_PASS="$5"

  mkdir -p /etc/sing-box

  if [ -f /etc/sing-box/config.json ]; then
    cp /etc/sing-box/config.json "/etc/sing-box/config.json.bak-$(date +%s)"
    warn "已备份旧 config.json"
  fi

  # 先写入临时文件
  local TMP_CONFIG="/tmp/sing-box-config-$$.json"
  
  cat > "$TMP_CONFIG" <<'EOFCONFIG'
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "cloudflare",
        "address": "1.1.1.1"
      }
    ]
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": VLESS_PORT_PLACEHOLDER,
      "users": [
        {
          "uuid": "VLESS_UUID_PLACEHOLDER",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "REALITY_DOMAIN_PLACEHOLDER",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "REALITY_DOMAIN_PLACEHOLDER",
            "server_port": 443
          },
          "private_key": "REALITY_PRIVATE_PLACEHOLDER",
          "short_id": ["SHORT_ID_PLACEHOLDER"]
        }
      }
    },
    {
      "type": "tuic",
      "tag": "tuic",
      "listen": "::",
      "listen_port": TUIC_PORT_PLACEHOLDER,
      "users": [
        {
          "uuid": "TUIC_UUID_PLACEHOLDER",
          "password": "TUIC_PASS_PLACEHOLDER"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "TUIC_CERT_PLACEHOLDER",
        "key_path": "TUIC_KEY_PLACEHOLDER"
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
    "auto_detect_interface": true,
    "rules": [
      {
        "protocol": ["bittorrent"],
        "outbound": "block"
      }
    ],
    "final": "direct"
  }
}
EOFCONFIG

  # 替换占位符
  sed -i "s/VLESS_PORT_PLACEHOLDER/${VLESS_PORT}/g" "$TMP_CONFIG"
  sed -i "s/TUIC_PORT_PLACEHOLDER/${TUIC_PORT}/g" "$TMP_CONFIG"
  sed -i "s/VLESS_UUID_PLACEHOLDER/${VLESS_UUID}/g" "$TMP_CONFIG"
  sed -i "s/TUIC_UUID_PLACEHOLDER/${TUIC_UUID}/g" "$TMP_CONFIG"
  sed -i "s/TUIC_PASS_PLACEHOLDER/${TUIC_PASS}/g" "$TMP_CONFIG"
  sed -i "s/REALITY_DOMAIN_PLACEHOLDER/${REALITY_DOMAIN}/g" "$TMP_CONFIG"
  sed -i "s|REALITY_PRIVATE_PLACEHOLDER|${REALITY_PRIVATE}|g" "$TMP_CONFIG"
  sed -i "s/SHORT_ID_PLACEHOLDER/${SHORT_ID}/g" "$TMP_CONFIG"
  sed -i "s|TUIC_CERT_PLACEHOLDER|${TUIC_CERT_PATH}|g" "$TMP_CONFIG"
  sed -i "s|TUIC_KEY_PLACEHOLDER|${TUIC_KEY_PATH}|g" "$TMP_CONFIG"

  log "配置已生成到临时文件: $TMP_CONFIG"
  log "开始检查 JSON 合法性..."

  # 设置环境变量以兼容旧版本检查（如果需要）
  export ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=false

  if ! sing-box check -c "$TMP_CONFIG" 2>&1 | tee /tmp/sing-box-check.log; then
    if grep -q "legacy DNS" /tmp/sing-box-check.log; then
      warn "检测到 DNS 格式警告，但配置已使用新格式，继续安装..."
    else
      err "配置检查失败！"
      err "临时配置文件保存在: $TMP_CONFIG"
      err "请检查后手动复制到 /etc/sing-box/config.json"
      exit 1
    fi
  fi
  
  log "配置合法 ✅"
  
  # 移动到正式位置
  mv "$TMP_CONFIG" /etc/sing-box/config.json
  log "配置已保存到 /etc/sing-box/config.json"
}

############## systemd 服务 ##############

setup_systemd() {
  cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable sing-box >/dev/null 2>&1 || true
  systemctl restart sing-box

  sleep 2
  log "Sing-box 服务状态："
  systemctl --no-pager -l status sing-box | sed -n '1,15p'
}

############## IP 检测 ##############

detect_ipv4() {
  local ip cand
  ip=$(curl -4s --max-time 5 https://api.ip.sb 2>/dev/null || true)
  cand=$(echo "$ip" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
  if [ -z "$cand" ]; then
    ip=$(curl -4s --max-time 5 https://ifconfig.me 2>/dev/null || true)
    cand=$(echo "$ip" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
  fi
  if [ -z "$cand" ]; then
    ip=$(curl -4s --max-time 5 https://ipv4.icanhazip.com 2>/dev/null || true)
    cand=$(echo "$ip" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
  fi
  echo "$cand"
}

############## 生成分享链接 & 二维码 ##############

gen_share_links() {
  local VLESS_PORT="$1"
  local TUIC_PORT="$2"
  local VLESS_UUID="$3"
  local TUIC_UUID="$4"
  local TUIC_PASS="$5"

  echo
  local SERVER_IP
  read -rp "服务器公网 IPv4 [回车自动检测]：" SERVER_IP
  if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(detect_ipv4)
  fi
  if [ -z "$SERVER_IP" ]; then
    err "自动检测 IP 失败，请重新运行脚本中的链接生成部分或手动写 IP。"
    return
  fi

  local VLESS_URL="vless://${VLESS_UUID}@${SERVER_IP}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#VLESS-REALITY"
  # 根据是否使用可信证书动态设置 allow_insecure 和标签
  local tuic_cert_label
  if [ "${TUIC_ALLOW_INSECURE}" -eq 0 ]; then
    tuic_cert_label="TUIC-v5 (Let's Encrypt 证书，域名: ${CUSTOM_DOMAIN:-已配置}):"
  else
    tuic_cert_label="TUIC-v5 (自签名证书):"
  fi
  local TUIC_URL="tuic://${TUIC_UUID}:${TUIC_PASS}@${SERVER_IP}:${TUIC_PORT}?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&allow_insecure=${TUIC_ALLOW_INSECURE}#TUIC-v5"

  mkdir -p /etc/sing-box
  cat > /etc/sing-box/share-links.txt <<EOF
VLESS-REALITY:
${VLESS_URL}

${tuic_cert_label}
${TUIC_URL}
EOF

  echo
  echo "================= 分享链接（已保存到 /etc/sing-box/share-links.txt） ================="
  echo "VLESS-REALITY:"
  echo "$VLESS_URL"
  echo
  echo "$tuic_cert_label"
  echo "$TUIC_URL"
  echo "==============================================================================="

  if command -v qrencode >/dev/null 2>&1; then
    echo
    log "生成二维码（终端显示）..."
    echo
    echo "【VLESS-REALITY 二维码】"
    echo "$VLESS_URL" | qrencode -t ANSIUTF8
    echo
    echo "【TUIC-v5 二维码】"
    echo "$TUIC_URL" | qrencode -t ANSIUTF8
    echo
    log "也可生成 PNG 文件："
    echo "$VLESS_URL" | qrencode -o /etc/sing-box/vless.png
    echo "$TUIC_URL"  | qrencode -o /etc/sing-box/tuic.png
    log "PNG 文件保存在：/etc/sing-box/vless.png, /etc/sing-box/tuic.png"
  else
    warn "未安装 qrencode，已跳过二维码生成。"
  fi
}

############## 主流程 ##############

setup_firewall() {
  log "配置防火墙规则..."
  
  if command -v ufw >/dev/null 2>&1; then
    # 允许 SSH（当前连接的端口）
    ufw allow 22/tcp 2>/dev/null || true
    
    # 允许 VPN 端口
    ufw allow "$1"/tcp  # VLESS
    ufw allow "$2"/udp  # TUIC
    
    # 启用防火墙（如果未启用）
    echo "y" | ufw enable 2>/dev/null || true
    ufw status
    
    log "✅ 防火墙已配置"
  elif command -v firewall-cmd >/dev/null 2>&1; then
    # CentOS/RHEL 使用 firewalld
    firewall-cmd --permanent --add-port="$1"/tcp
    firewall-cmd --permanent --add-port="$2"/udp
    firewall-cmd --reload
    log "✅ 防火墙已配置"
  else
    warn "未检测到 ufw 或 firewalld，请手动配置防火墙开放端口 $1(TCP) 和 $2(UDP)"
  fi
}

do_install() {
  install_base
  check_prereqs
  enable_bbr
  need_cmd curl
  need_cmd wget
  need_cmd jq
  install_sing_box
  choose_reality_domain
  generate_reality_keys

  echo
  read -rp "VLESS Reality 端口 [默认: 443]：" VLESS_PORT
  VLESS_PORT=${VLESS_PORT:-443}
  read -rp "TUIC 端口 [默认: 8443]：" TUIC_PORT
  TUIC_PORT=${TUIC_PORT:-8443}
  log "✅ VLESS 端口: ${VLESS_PORT}"
  log "✅ TUIC  端口: ${TUIC_PORT}"

  local VLESS_UUID TUIC_UUID TUIC_PASS
  VLESS_UUID=$(generate_uuid)
  TUIC_UUID=$(generate_uuid)
  TUIC_PASS=$(generate_uuid)

  generate_self_signed_cert
  setup_custom_domain
  write_config "$VLESS_PORT" "$TUIC_PORT" "$VLESS_UUID" "$TUIC_UUID" "$TUIC_PASS"
  setup_firewall "$VLESS_PORT" "$TUIC_PORT"
  setup_systemd
  gen_share_links "$VLESS_PORT" "$TUIC_PORT" "$VLESS_UUID" "$TUIC_UUID" "$TUIC_PASS"

  echo
  log "🎉 全部完成！"
  echo
  echo "============== 🔐 安全建议 =============="
  echo "1. 定期更新系统：apt update && apt upgrade"
  echo "2. 修改 SSH 端口并禁用密码登录（只用密钥）"
  echo "3. 定期检查流量使用：可用 vnstat 监控"
  echo "4. 不要分享链接给不信任的人"
  echo "5. 定期更改 UUID：重新运行本脚本即可"
  echo "6. 监控服务状态：systemctl status sing-box"
  echo "========================================"
  echo
  echo "============== 📱 客户端导入 =============="
  echo "1）安卓 NekoBox / v2rayNG：扫码或粘贴链接"
  echo "2）iOS Shadowrocket：扫码导入"
  echo "3）Mac/Win sing-box / v2rayN：新建节点粘贴链接"
  echo "4）二维码已在上方显示，也可在 /etc/sing-box/ 下载 PNG"
  echo "=========================================="
}

main() {
  # 显示菜单
  while true; do
    show_menu
    read -rp "请选择操作 [0-17]: " choice

    case "$choice" in
      1)
        log "开始全新安装 Sing-box..."
        do_install
        break
        ;;
      2)
        clean_old_install
        log "开始重新安装..."
        do_install
        break
        ;;
      3)
        clean_old_install
        log "清理完成！"
        break
        ;;
      4)
        uninstall_singbox
        break
        ;;
      5)
        show_current_config
        echo
        read -rp "按回车键继续..."
        ;;
      6)
        diagnose_connection
        echo
        read -rp "按回车键继续..."
        ;;
      7)
        deep_clean
        read -rp "是否立即重新安装？(y/n): " reinstall
        if [[ "$reinstall" =~ ^[Yy]$ ]]; then
          do_install
        fi
        break
        ;;
      8)
        query_reality_domain
        echo
        read -rp "按回车键继续..."
        ;;
      9)
        update_reality_domain
        echo
        read -rp "按回车键继续..."
        ;;
      10)
        full_health_check
        echo
        read -rp "按回车键继续..."
        ;;
      11)
        reload_share_links
        echo
        read -rp "按回车键继续..."
        ;;
      12)
        install_snell
        echo
        read -rp "按回车键继续..."
        ;;
      13)
        show_snell_config
        echo
        read -rp "按回车键继续..."
        ;;
      14)
        uninstall_snell
        echo
        read -rp "按回车键继续..."
        ;;
      15)
        restart_snell
        echo
        read -rp "按回车键继续..."
        ;;
      16)
        regenerate_snell_config
        echo
        read -rp "按回车键继续..."
        ;;
      17)
        diagnose_snell
        echo
        read -rp "按回车键继续..."
        ;;
      18)
        configure_custom_domain_cert
        echo
        read -rp "按回车键继续..."
        ;;
      0)
        log "退出脚本"
        exit 0
        ;;
      *)
        err "无效选择，请重新输入 [0-17]"
        echo
        ;;
    esac
  done
}

main "$@"
