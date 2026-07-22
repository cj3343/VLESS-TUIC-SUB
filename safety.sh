#!/usr/bin/env bash
# VPN server safety hardening helper
# Safe defaults: protect services without locking yourself out.
#
# 定位：防火墙放行 + Fail2Ban + SSH 辅助（防锁死优先）
# 不默认禁用 SSH 密码；密钥加固为独立高风险菜单项。
# 不自动对公网开放 3x-ui 面板（可用白名单菜单）。

set -u

SAFETY_VERSION="1.3.1"
BACKUP_DIR="/root/safety-backups"
SSH_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSH_DROPIN_FILE="${SSH_DROPIN_DIR}/99-safety-hardening.conf"

log()  { echo -e "\033[32m[INFO]\033[0m $*"; }
warn() { echo -e "\033[33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[31m[ERR ]\033[0m $*" >&2; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "请用 root 运行：sudo bash safety.sh"
    return 1
  fi
}

is_valid_port() {
  local port="${1:-}"
  [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

# IPv4 地址：每段 0–255
_is_valid_ipv4() {
  local addr="${1:-}" o1 o2 o3 o4
  [[ "$addr" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  o1="${BASH_REMATCH[1]}"
  o2="${BASH_REMATCH[2]}"
  o3="${BASH_REMATCH[3]}"
  o4="${BASH_REMATCH[4]}"
  # 禁止前导零（可选：放宽则删下面四行）；统一按十进制范围校验
  [ "$o1" -ge 0 ] && [ "$o1" -le 255 ] || return 1
  [ "$o2" -ge 0 ] && [ "$o2" -le 255 ] || return 1
  [ "$o3" -ge 0 ] && [ "$o3" -le 255 ] || return 1
  [ "$o4" -ge 0 ] && [ "$o4" -le 255 ] || return 1
  return 0
}

# IPv6：仅十六进制与冒号；至多一个 ::；可选 /0–128
_is_valid_ipv6() {
  local addr="${1:-}" tmp
  [[ "$addr" =~ ^[0-9a-fA-F:]+$ ]] || return 1
  [[ "$addr" == *:* ]] || return 1
  [[ "$addr" =~ ::: ]] && return 1
  if [[ "$addr" == *"::"* ]]; then
    tmp="${addr/::/}"
    [[ "$tmp" == *"::"* ]] && return 1
  fi
  # 每个 hextet 最多 4 位
  local part
  tmp="${addr//::/:}"
  IFS=':' read -ra _hextets <<<"$tmp"
  for part in "${_hextets[@]}"; do
    [ -z "$part" ] && continue
    [[ "$part" =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1
  done
  return 0
}

# 接受 IPv4、IPv4/CIDR、IPv6、IPv6/CIDR（拒绝 999.999.999.999 等）
is_valid_ip() {
  local raw="${1:-}" addr pfx
  [ -n "$raw" ] || return 1

  if [[ "$raw" == */* ]]; then
    addr="${raw%/*}"
    pfx="${raw#*/}"
    # 前缀里不能再有 /
    [[ "$pfx" == *"/"* ]] && return 1
    [[ -n "$addr" && -n "$pfx" ]] || return 1
  else
    addr="$raw"
    pfx=""
  fi

  if [[ "$addr" == *:* ]]; then
    if [ -n "$pfx" ]; then
      [[ "$pfx" =~ ^(0|[1-9][0-9]?|1[01][0-9]|12[0-8])$ ]] || return 1
    fi
    _is_valid_ipv6 "$addr"
    return $?
  fi

  if [ -n "$pfx" ]; then
    [[ "$pfx" =~ ^([0-9]|[12][0-9]|3[0-2])$ ]] || return 1
  fi
  _is_valid_ipv4 "$addr"
}

is_ipv6_addr() {
  local ip="${1%%/*}"
  [[ "$ip" == *:* ]]
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

confirm_yes() {
  local prompt="${1:-确认？(yes/no): }"
  local ans
  read -rp "$prompt" ans
  [ "$ans" = "yes" ]
}

ts() {
  date +%Y%m%d%H%M%S
}

ensure_backup_dir() {
  mkdir -p "$BACKUP_DIR"
}

# ---------------------------------------------------------------------------
# 防火墙检测 / 依赖
# ---------------------------------------------------------------------------

detect_firewall() {
  if need_cmd ufw; then
    echo "ufw"
  elif need_cmd firewall-cmd; then
    echo "firewalld"
  else
    echo "none"
  fi
}

install_dependencies() {
  require_root || return 1

  local pkgs="curl jq ca-certificates"
  local rc=0

  if need_cmd apt-get; then
    apt-get update -qq || rc=1
    apt-get install -y -qq $pkgs ufw fail2ban sqlite3 || rc=1
  elif need_cmd dnf; then
    dnf install -y -q $pkgs firewalld fail2ban sqlite || rc=1
  elif need_cmd yum; then
    yum install -y -q $pkgs firewalld fail2ban sqlite || rc=1
  else
    err "无法自动安装依赖，请手动安装：curl jq 防火墙 fail2ban"
    return 1
  fi

  if ! need_cmd jq; then
    err "jq 安装失败或不可用，无法安全识别 VPN 端口"
    return 1
  fi

  if [ "$rc" -ne 0 ]; then
    warn "部分依赖安装可能失败，请检查 ufw/firewalld 与 fail2ban"
  fi

  log "依赖检查完成"
  return 0
}

install_firewall_if_needed() {
  require_root || return 1
  if [ "$(detect_firewall)" != "none" ]; then
    return 0
  fi

  log "未检测到防火墙，开始安装..."
  if need_cmd apt-get; then
    apt-get update -qq && apt-get install -y -qq ufw || {
      err "ufw 安装失败"
      return 1
    }
  elif need_cmd dnf; then
    dnf install -y -q firewalld || {
      err "firewalld 安装失败"
      return 1
    }
  elif need_cmd yum; then
    yum install -y -q firewalld || {
      err "firewalld 安装失败"
      return 1
    }
  else
    err "无法自动安装防火墙"
    return 1
  fi

  if [ "$(detect_firewall)" = "none" ]; then
    err "防火墙安装后仍不可用"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# SSH / 客户端 IP
# ---------------------------------------------------------------------------

get_ssh_ports() {
  local ports
  ports=$(
    {
      sshd -T 2>/dev/null | awk '/^port / {print $2}'
      # shellcheck disable=SC2086
      grep -RhsE '^[[:space:]]*Port[[:space:]]+[0-9]+' \
        /etc/ssh/sshd_config ${SSH_DROPIN_DIR}/*.conf 2>/dev/null | awk '{print $2}'
    } | grep -E '^[0-9]+$' | sort -n -u
  )
  if [ -n "$ports" ]; then
    echo "$ports"
  else
    echo 22
  fi
}

get_current_client_ip() {
  local ip=""
  if [ -n "${SSH_CLIENT:-}" ]; then
    ip="${SSH_CLIENT%% *}"
  elif [ -n "${SSH_CONNECTION:-}" ]; then
    ip="${SSH_CONNECTION%% *}"
  fi
  if [ -n "$ip" ] && is_valid_ip "$ip"; then
    echo "$ip"
  fi
}

# ---------------------------------------------------------------------------
# 端口放行
# ---------------------------------------------------------------------------

allow_port() {
  local port="$1"
  local proto="${2:-tcp}"
  local name="${3:-service}"
  local fw

  if ! is_valid_port "$port"; then
    warn "跳过无效端口：${name} ${port}/${proto}"
    return 0
  fi

  fw=$(detect_firewall)
  case "$fw" in
    ufw)
      if ufw allow "${port}/${proto}" comment "${name}" >/dev/null 2>&1 || \
         ufw allow "${port}/${proto}" >/dev/null 2>&1; then
        log "已放行：${name} ${port}/${proto}"
        return 0
      fi
      warn "ufw 放行失败：${name} ${port}/${proto}"
      return 1
      ;;
    firewalld)
      systemctl enable --now firewalld >/dev/null 2>&1 || true
      if firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1; then
        log "已放行：${name} ${port}/${proto}"
        return 0
      fi
      warn "firewalld 放行失败：${name} ${port}/${proto}"
      return 1
      ;;
    *)
      warn "未检测到防火墙，无法放行：${name} ${port}/${proto}"
      return 1
      ;;
  esac
}

allow_ssh_ports() {
  local p rc=0
  for p in $(get_ssh_ports); do
    allow_port "$p" tcp "SSH" || rc=1
  done
  return "$rc"
}

# 仅允许来自指定源 IP 的端口（面板白名单）
allow_port_from() {
  local src="$1"
  local port="$2"
  local proto="${3:-tcp}"
  local name="${4:-service}"
  local fw family rule

  if ! is_valid_ip "$src"; then
    err "无效源地址：$src"
    return 1
  fi
  if ! is_valid_port "$port"; then
    err "无效端口：$port"
    return 1
  fi

  fw=$(detect_firewall)
  case "$fw" in
    ufw)
      if ufw allow from "$src" to any port "$port" proto "$proto" comment "${name}" >/dev/null 2>&1 || \
         ufw allow from "$src" to any port "$port" proto "$proto" >/dev/null 2>&1; then
        log "已白名单放行：${name} ${port}/${proto} from ${src}"
        return 0
      fi
      warn "ufw 白名单放行失败：${name} ${port}/${proto} from ${src}"
      return 1
      ;;
    firewalld)
      systemctl enable --now firewalld >/dev/null 2>&1 || true
      if is_ipv6_addr "$src"; then
        family="ipv6"
      else
        family="ipv4"
      fi
      rule="rule family=\"${family}\" source address=\"${src}\" port port=\"${port}\" protocol=\"${proto}\" accept"
      if firewall-cmd --permanent --add-rich-rule="${rule}" >/dev/null 2>&1; then
        firewall-cmd --reload >/dev/null 2>&1 || true
        log "已白名单放行：${name} ${port}/${proto} from ${src}"
        return 0
      fi
      warn "firewalld 白名单放行失败：${name} ${port}/${proto} from ${src}"
      return 1
      ;;
    *)
      err "未检测到防火墙，无法配置白名单"
      return 1
      ;;
  esac
}

# ---------------------------------------------------------------------------
# 服务端口识别
# ---------------------------------------------------------------------------

_emit_port() {
  local port="$1" proto="$2" name="$3"
  is_valid_port "$port" || return 0
  printf "%s\t%s\t%s\n" "$port" "$proto" "$name"
}

collect_singbox_ports() {
  local cfg="/etc/sing-box/config.json"
  [ -f "$cfg" ] || return 0
  if ! need_cmd jq; then
    warn "存在 $cfg 但缺少 jq，无法解析 sing-box 端口"
    return 0
  fi

  jq -r '
    .inbounds[]? // empty
    | select(.listen_port != null)
    | . as $in
    | ($in.listen // "0.0.0.0") as $listen
    | select(($listen | tostring) != "127.0.0.1" and ($listen | tostring) != "::1")
    | ($in.type // "inbound") as $type
    | ($in.listen_port | tonumber) as $port
    | if ($type == "tuic" or $type == "hysteria" or $type == "hysteria2" or $type == "wireguard") then
        "\($port)\tudp\tsing-box/\($type)"
      elif ($type == "shadowsocks" or $type == "mixed" or $type == "naive") then
        "\($port)\ttcp\tsing-box/\($type)",
        "\($port)\tudp\tsing-box/\($type)"
      else
        "\($port)\ttcp\tsing-box/\($type)"
      end
  ' "$cfg" 2>/dev/null
}

# 仅探测面板端口，绝不写入放行清单（管理面不应默认对公网开放）
detect_xui_panel_port() {
  local port="" db f

  for f in /usr/local/x-ui/bin/config.json /etc/x-ui/config.json; do
    if [ -f "$f" ] && need_cmd jq; then
      port=$(jq -r '.webPort // .panelPort // empty' "$f" 2>/dev/null | head -n 1)
      if is_valid_port "${port:-}"; then
        echo "$port"
        return 0
      fi
    fi
  done

  if need_cmd sqlite3; then
    for db in /etc/x-ui/x-ui.db /usr/local/x-ui/x-ui.db; do
      [ -f "$db" ] || continue
      port=$(sqlite3 "$db" \
        "SELECT value FROM settings WHERE key IN ('webPort','panelPort') LIMIT 1;" \
        2>/dev/null | head -n 1)
      if is_valid_port "${port:-}"; then
        echo "$port"
        return 0
      fi
    done
  fi
  return 1
}

# Xray/3x-ui：默认只放 tcp；仅 network=kcp|quic|udp 或 protocol=wireguard 才加 udp
# 参数：jq 迭代表达式，如 '.inbounds[]?' 或 '.[]?'
_xui_jq_emit() {
  local each="${1:-.[]?}"
  jq -r "
    def stream_net:
      (
        .streamSettings.network
        // (try (.stream_settings | if type == \"string\" then fromjson else . end | .network) catch null)
        // .network
        // .stream_network
        // \"tcp\"
      ) | ascii_downcase;
    def needs_udp:
      (stream_net == \"kcp\" or stream_net == \"quic\" or stream_net == \"udp\")
      or ((.protocol // \"\") | ascii_downcase) == \"wireguard\";
    ${each} // empty
    | select(.port != null)
    | select((.listen // \"0.0.0.0\") != \"127.0.0.1\")
    | select((.protocol // \"\") != \"tunnel\")
    | (.port | tonumber) as \$port
    | (.protocol // \"xray\") as \$proto
    | \"\\(\$port)\\ttcp\\t3x-ui/\\(\$proto)\",
      (if needs_udp then \"\\(\$port)\\tudp\\t3x-ui/\\(\$proto)\" else empty end)
  " 2>/dev/null
}

collect_xui_inbound_ports() {
  local cfg="/usr/local/x-ui/bin/config.json"
  local db

  if [ -f "$cfg" ] && need_cmd jq; then
    _xui_jq_emit '.inbounds[]?' <"$cfg"
  fi

  if need_cmd sqlite3 && need_cmd jq; then
    for db in /etc/x-ui/x-ui.db /usr/local/x-ui/x-ui.db; do
      [ -f "$db" ] || continue
      local rows=""
      # 优先带 stream_settings（用于判断 kcp/quic）
      rows=$(sqlite3 -json "$db" \
        "SELECT port, protocol, listen, enable, stream_settings FROM inbounds WHERE enable = 1;" \
        2>/dev/null || true)
      if [ -z "$rows" ] || [ "$rows" = "[]" ]; then
        rows=$(sqlite3 -json "$db" \
          "SELECT port, protocol, listen, enable FROM inbounds WHERE enable = 1;" \
          2>/dev/null || true)
      fi
      if [ -n "$rows" ] && [ "$rows" != "[]" ]; then
        printf '%s\n' "$rows" | _xui_jq_emit '.[]?' || true
      fi

      # 模板配置：按同样规则解析
      rows=$(sqlite3 "$db" "SELECT value FROM settings WHERE key = 'xrayTemplateConfig' LIMIT 1;" 2>/dev/null || true)
      if [ -n "$rows" ]; then
        printf '%s\n' "$rows" | jq -c 'try fromjson catch empty' 2>/dev/null \
          | _xui_jq_emit '.inbounds[]?' || true
      fi
    done
  fi
}

collect_snell_ports() {
  local conf="/etc/snell/snell-server.conf" p
  [ -f "$conf" ] || return 0
  p=$(grep -E '^listen[[:space:]]*=' "$conf" 2>/dev/null | grep -Eo '[0-9]+' | tail -n 1 || true)
  [ -n "${p:-}" ] && _emit_port "$p" tcp "Snell"
}

collect_ssrust_ports() {
  local cfg="/etc/shadowsocks-rust/config.json" p
  [ -f "$cfg" ] || return 0
  if ! need_cmd jq; then
    warn "存在 $cfg 但缺少 jq"
    return 0
  fi
  p=$(jq -r '.server_port // empty' "$cfg" 2>/dev/null | head -n 1)
  if [ -n "${p:-}" ]; then
    _emit_port "$p" tcp "shadowsocks-rust"
    _emit_port "$p" udp "shadowsocks-rust"
  fi
}

collect_caddy_ports() {
  if systemctl cat caddy >/dev/null 2>&1 || \
     systemctl is-enabled --quiet caddy 2>/dev/null || \
     systemctl is-active --quiet caddy 2>/dev/null; then
    _emit_port 80 tcp "Caddy HTTP"
    _emit_port 443 tcp "Caddy HTTPS"
    _emit_port 443 udp "Caddy HTTP3"
  fi
}

vpn_config_present() {
  [ -f /etc/sing-box/config.json ] && return 0
  [ -f /usr/local/x-ui/bin/config.json ] && return 0
  [ -f /etc/x-ui/x-ui.db ] && return 0
  [ -f /usr/local/x-ui/x-ui.db ] && return 0
  [ -f /etc/snell/snell-server.conf ] && return 0
  [ -f /etc/shadowsocks-rust/config.json ] && return 0
  return 1
}

require_jq_if_needed() {
  if vpn_config_present && ! need_cmd jq; then
    err "检测到 VPN 配置文件，但系统没有 jq，拒绝启用防火墙（避免漏放端口）"
    err "请先安装 jq：apt-get install -y jq  或  dnf install -y jq"
    return 1
  fi
  return 0
}

collect_service_ports() {
  # 注意：故意不包含 3x-ui 面板端口（管理面不对公网默认放行）
  collect_singbox_ports
  collect_xui_inbound_ports
  collect_snell_ports
  collect_ssrust_ports
  collect_caddy_ports
}

sorted_service_ports() {
  collect_service_ports | sort -t$'\t' -k1,1n -k2,2 -u
}

# 是否识别到「节点」端口（排除纯 Web/Caddy，用于强提醒）
has_node_ports() {
  sorted_service_ports 2>/dev/null | grep -vE $'\tCaddy' | grep -q .
}

warn_if_no_node_ports() {
  if has_node_ports; then
    return 0
  fi
  err "未识别到节点（VPN）端口！"
  err "启用防火墙后 default deny incoming，代理将不可用。"
  err "请先检查：jq/sqlite3、sing-box/3x-ui 配置是否可读；或手动 ufw allow <端口>/tcp"
  err "若列表里没有节点端口，请不要继续。"
  return 1
}

show_detected_ports() {
  local lines panel
  echo "========================================"
  echo "检测到的服务端口"
  echo "========================================"
  echo "SSH:"
  get_ssh_ports | sed 's/^/  - /'
  echo
  echo "将自动放行的 VPN / Web 端口:"
  lines=$(sorted_service_ports || true)
  if [ -z "${lines:-}" ]; then
    warn "  （未识别到任何可自动放行的节点端口）"
    warn "  列表为空时不要启用防火墙，否则节点会断"
  else
    echo "$lines" | awk -F'\t' '{printf "  - %-6s %-4s %s\n", $1, $2, $3}'
  fi
  echo
  echo "3x-ui 面板（不自动放行）:"
  panel=$(detect_xui_panel_port || true)
  if [ -n "${panel:-}" ]; then
    warn "  - ${panel}/tcp  已识别，但默认不对公网开放"
    warn "  - 建议：固定 IP 白名单，或 SSH 隧道访问面板"
    warn "  - 手动放行示例: ufw allow from <你的IP> to any port ${panel} proto tcp"
  else
    echo "  - （未检测到面板端口）"
  fi
  echo "========================================"
}

# ---------------------------------------------------------------------------
# 防火墙启用
# ---------------------------------------------------------------------------

backup_firewall_state() {
  ensure_backup_dir
  local stamp fw out
  stamp=$(ts)
  fw=$(detect_firewall)
  out="${BACKUP_DIR}/firewall-${fw}-${stamp}.txt"
  case "$fw" in
    ufw)
      {
        echo "# ufw backup $(date)"
        ufw status verbose 2>/dev/null || true
        echo
        ufw status numbered 2>/dev/null || true
      } >"$out"
      ;;
    firewalld)
      {
        echo "# firewalld backup $(date)"
        firewall-cmd --list-all 2>/dev/null || true
        echo
        firewall-cmd --list-all-zones 2>/dev/null || true
      } >"$out"
      ;;
    *)
      return 0
      ;;
  esac
  log "防火墙状态已备份：$out"
}

enable_firewall_safe() {
  require_root || return 1
  require_jq_if_needed || return 1
  install_firewall_if_needed || return 1

  local fw fail=0
  fw=$(detect_firewall)

  echo
  show_detected_ports
  echo
  if ! warn_if_no_node_ports; then
    if ! confirm_yes "确认没有节点端口仍要继续（节点将断）？(yes/no): "; then
      log "已取消"
      return 0
    fi
    if ! confirm_yes "再次确认：将只放行 SSH + 列表项，default deny 其余。继续？(yes/no): "; then
      log "已取消"
      return 0
    fi
  fi
  if ! confirm_yes "确认按上述清单放行并启用防火墙？(yes/no): "; then
    log "已取消"
    return 0
  fi

  backup_firewall_state

  log "先放行 SSH 端口，避免锁死..."
  allow_ssh_ports || fail=1

  log "放行已识别的 VPN/Web 服务端口..."
  while IFS=$'\t' read -r port proto name; do
    [ -n "${port:-}" ] || continue
    allow_port "$port" "$proto" "$name" || fail=1
  done < <(sorted_service_ports)

  case "$fw" in
    ufw)
      ufw default deny incoming >/dev/null 2>&1 || warn "设置 default deny incoming 失败"
      ufw default allow outgoing >/dev/null 2>&1 || warn "设置 default allow outgoing 失败"
      ufw default deny routed >/dev/null 2>&1 || true
      if ! ufw --force enable >/dev/null 2>&1; then
        err "ufw enable 失败"
        return 1
      fi
      log "ufw 已启用"
      ufw status verbose
      ;;
    firewalld)
      systemctl enable --now firewalld >/dev/null 2>&1 || true
      if ! firewall-cmd --reload >/dev/null 2>&1; then
        err "firewalld reload 失败"
        return 1
      fi
      log "firewalld 已 reload"
      firewall-cmd --list-all
      ;;
    *)
      err "未检测到可用防火墙"
      return 1
      ;;
  esac

  if [ "$fail" -ne 0 ]; then
    warn "部分端口放行失败，请核对上方日志"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Fail2Ban
# ---------------------------------------------------------------------------

setup_fail2ban_safe() {
  require_root || return 1

  if ! need_cmd fail2ban-client; then
    log "安装 fail2ban 及依赖..."
    install_dependencies || return 1
  fi
  if ! need_cmd fail2ban-client; then
    err "fail2ban 不可用"
    return 1
  fi

  local ssh_ports ignore_ip client_ip banaction backend_block stamp jail_backup
  ssh_ports=$(get_ssh_ports | paste -sd, - 2>/dev/null || echo 22)
  ssh_ports=${ssh_ports:-22}
  ignore_ip="127.0.0.1/8 ::1"
  client_ip=$(get_current_client_ip || true)
  if [ -n "${client_ip:-}" ]; then
    ignore_ip="${ignore_ip} ${client_ip}"
    log "Fail2Ban ignoreip 加入当前 SSH 客户端：${client_ip}"
  else
    warn "未能识别当前 SSH 客户端 IP（非 SSH 会话？），请稍后手动加入 ignoreip"
  fi

  banaction=""
  case "$(detect_firewall)" in
    ufw) banaction="ufw" ;;
    firewalld) banaction="firewallcmd-rich-rules" ;;
  esac

  # 优先 journald，兼容各发行版
  if need_cmd systemctl && systemctl is-system-running >/dev/null 2>&1 || \
     [ -d /run/systemd/system ]; then
    backend_block="backend = systemd"
  elif [ -f /var/log/auth.log ]; then
    backend_block="backend = auto
logpath = /var/log/auth.log"
  elif [ -f /var/log/secure ]; then
    backend_block="backend = auto
logpath = /var/log/secure"
  else
    backend_block="backend = systemd"
    warn "未找到 auth.log/secure，使用 systemd backend"
  fi

  ensure_backup_dir
  stamp=$(ts)
  if [ -f /etc/fail2ban/jail.local ]; then
    jail_backup="${BACKUP_DIR}/jail.local.${stamp}.bak"
    cp -a /etc/fail2ban/jail.local "$jail_backup"
    log "已备份 jail.local → $jail_backup"
  fi

  {
    cat <<EOF
# Generated by safety.sh $(date)
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
ignoreip = ${ignore_ip}
EOF
    if [ -n "$banaction" ]; then
      echo "banaction = ${banaction}"
    fi
    cat <<EOF

[sshd]
enabled = true
port    = ${ssh_ports}
filter  = sshd
${backend_block}
maxretry = 5
bantime  = 3600
EOF
  } > /etc/fail2ban/jail.local

  systemctl enable fail2ban >/dev/null 2>&1 || true
  if ! systemctl restart fail2ban; then
    err "fail2ban 重启失败，请检查 /etc/fail2ban/jail.local"
    return 1
  fi
  sleep 1
  if fail2ban-client status sshd >/dev/null 2>&1; then
    log "Fail2Ban sshd jail 运行正常"
    fail2ban-client status sshd
  else
    warn "sshd jail 未就绪，显示服务状态："
    systemctl status fail2ban --no-pager | sed -n '1,20p' || true
    return 1
  fi
}

# ---------------------------------------------------------------------------
# SSH 健康 / 密钥加固
# ---------------------------------------------------------------------------

check_ssh_health() {
  echo "========================================"
  echo "SSH 健康检查"
  echo "========================================"
  systemctl status ssh --no-pager 2>/dev/null | sed -n '1,12p' || \
    systemctl status sshd --no-pager 2>/dev/null | sed -n '1,12p' || true
  echo
  echo "有效 SSH 配置 (sshd -T):"
  sshd -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|maxstartups|maxauthtries|allowusers|denyusers)' || true
  echo
  echo "authorized_keys:"
  if [ -f /root/.ssh/authorized_keys ]; then
    wc -l /root/.ssh/authorized_keys
  else
    warn "/root/.ssh/authorized_keys 不存在"
  fi
  echo "========================================"
}

# OpenSSH 多数关键字 first-obtained wins：必须清掉先读入的冲突项
_comment_ssh_conflicts() {
  local f
  local patterns='PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PermitRootLogin|PubkeyAuthentication|PermitEmptyPasswords|MaxAuthTries|LoginGraceTime|X11Forwarding'

  for f in /etc/ssh/sshd_config ${SSH_DROPIN_DIR}/*.conf; do
    [ -f "$f" ] || continue
    # 跳过我们自己将写入的文件
    [ "$(basename "$f")" = "99-safety-hardening.conf" ] && continue
    if grep -qE "^[[:space:]]*(#[[:space:]]*)?(${patterns})[[:space:]]+" "$f" 2>/dev/null; then
      cp -a "$f" "${f}.bak-safety-$(ts)" 2>/dev/null || true
      # 注释掉生效中的相关指令（保留原行内容）
      sed -i -E "s/^([[:space:]]*)(${patterns})([[:space:]]+.*)$/\1# disabled-by-safety: \2\3/" "$f"
      log "已注释冲突项：$f"
    fi
  done
}

# 从 backup_root 恢复 SSH；处理「原本没有 sshd_config.d」时新建 drop-in 的回滚
# 参数: $1=backup_root  $2=dropin_dir_existed(0/1)
_restore_ssh_config() {
  local backup_root="$1"
  local dropin_dir_existed="${2:-0}"

  if [ -f "$backup_root/sshd_config" ]; then
    cp -a "$backup_root/sshd_config" /etc/ssh/sshd_config 2>/dev/null || true
  fi

  if [ -d "$backup_root/sshd_config.d" ]; then
    # 加固前已有 drop-in 目录：整目录还原
    rm -rf "$SSH_DROPIN_DIR"
    cp -a "$backup_root/sshd_config.d" "$SSH_DROPIN_DIR"
    log "已还原 $SSH_DROPIN_DIR"
  else
    # 加固前没有 drop-in 目录（或未备份到）：删掉我们写入的文件
    rm -f "$SSH_DROPIN_FILE"
    if [ "$dropin_dir_existed" -eq 0 ] && [ -d "$SSH_DROPIN_DIR" ]; then
      # 仅当我们创建了目录且现在为空（或只剩无关残留）时尽量删掉
      rm -f "${SSH_DROPIN_DIR}/99-safety-hardening.conf"
      rmdir "$SSH_DROPIN_DIR" 2>/dev/null || true
      if [ -d "$SSH_DROPIN_DIR" ]; then
        warn "未能移除 $SSH_DROPIN_DIR（目录非空），已删除 safety drop-in"
      else
        log "已移除新建的 $SSH_DROPIN_DIR"
      fi
    else
      log "已删除 drop-in：$SSH_DROPIN_FILE"
    fi
  fi
}

ssh_key_only_harden() {
  require_root || return 1
  warn "高风险操作：禁用密码登录前，必须确认密钥登录可用。"
  warn "建议：保持当前会话，另开一个终端验证密钥登录成功后再继续。"

  local pub_key
  read -rp "请输入 root 公钥，留空则仅使用现有 authorized_keys: " pub_key

  if [ -n "$pub_key" ]; then
    if ! echo "$pub_key" | grep -qE '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) '; then
      err "公钥格式不正确（支持 ed25519/rsa/ecdsa/sk-*）"
      return 1
    fi
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    echo "$pub_key" >> /root/.ssh/authorized_keys
    sort -u -o /root/.ssh/authorized_keys /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    log "公钥已写入 /root/.ssh/authorized_keys"
  fi

  if [ ! -s /root/.ssh/authorized_keys ]; then
    err "没有可用 authorized_keys，禁止继续"
    return 1
  fi

  if ! confirm_yes "已在新终端用密钥登录成功？输入 yes 才会禁用密码: "; then
    log "已取消"
    return 0
  fi

  ensure_backup_dir
  local stamp backup_root dropin_dir_existed=0
  stamp=$(ts)
  backup_root="${BACKUP_DIR}/ssh-${stamp}"
  mkdir -p "$backup_root"

  # 记录加固前是否已有 drop-in 目录（回滚时要区分）
  if [ -d "$SSH_DROPIN_DIR" ]; then
    dropin_dir_existed=1
  fi

  cp -a /etc/ssh/sshd_config "$backup_root/" 2>/dev/null || true
  if [ "$dropin_dir_existed" -eq 1 ]; then
    cp -a "$SSH_DROPIN_DIR" "$backup_root/sshd_config.d" 2>/dev/null || true
  fi
  # 标记，便于人工排查
  echo "dropin_dir_existed=${dropin_dir_existed}" >"$backup_root/meta.txt"
  log "SSH 配置已备份：$backup_root (dropin_dir_existed=${dropin_dir_existed})"

  # 使用 drop-in；若无 d 目录则创建后写入
  if [ -d "$SSH_DROPIN_DIR" ] || mkdir -p "$SSH_DROPIN_DIR" 2>/dev/null; then
    _comment_ssh_conflicts
    cat > "$SSH_DROPIN_FILE" <<'EOF'
# Generated by safety.sh — SSH key-only hardening
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
PermitEmptyPasswords no
MaxAuthTries 5
LoginGraceTime 30
X11Forwarding no
EOF
    log "已写入 $SSH_DROPIN_FILE"
  else
    _comment_ssh_conflicts
    # 主文件追加（冲突项已注释）；主文件已在 backup_root
    cat >> /etc/ssh/sshd_config <<'EOF'

# --- safety.sh hardening ---
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
PermitEmptyPasswords no
MaxAuthTries 5
LoginGraceTime 30
X11Forwarding no
EOF
  fi

  if ! sshd -t 2>/tmp/sshd-safety-test.log; then
    err "sshd -t 失败，正在从备份恢复..."
    cat /tmp/sshd-safety-test.log >&2 || true
    _restore_ssh_config "$backup_root" "$dropin_dir_existed"
    return 1
  fi

  if ! systemctl restart ssh 2>/dev/null && ! systemctl restart sshd 2>/dev/null; then
    err "SSH 重启失败，正在恢复备份..."
    _restore_ssh_config "$backup_root" "$dropin_dir_existed"
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    return 1
  fi

  local effective
  effective=$(sshd -T 2>/dev/null | awk '/^passwordauthentication / {print $2}')
  if [ "$effective" != "no" ]; then
    err "sshd -T 显示 passwordauthentication=${effective:-unknown}，加固未生效，正在回滚..."
    _restore_ssh_config "$backup_root" "$dropin_dir_existed"
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    return 1
  fi

  log "SSH 密钥登录加固完成。passwordauthentication=no"
  log "备份目录：$backup_root"
  check_ssh_health
}

# ---------------------------------------------------------------------------
# 状态 / 一键加固
# ---------------------------------------------------------------------------

status_report() {
  echo "========================================"
  echo "安全状态"
  echo "========================================"
  echo "时间: $(date)"
  echo "主机: $(hostname)"
  echo "防火墙后端: $(detect_firewall)"
  echo
  show_detected_ports
  echo
  echo "防火墙规则:"
  case "$(detect_firewall)" in
    ufw) ufw status verbose ;;
    firewalld) firewall-cmd --list-all ;;
    *) echo "未检测到 ufw/firewalld" ;;
  esac
  echo
  echo "Fail2Ban:"
  if need_cmd fail2ban-client; then
    fail2ban-client status sshd 2>/dev/null || \
      systemctl status fail2ban --no-pager 2>/dev/null | sed -n '1,12p' || true
  else
    echo "未安装 fail2ban"
  fi
  echo
  check_ssh_health
}

safe_harden() {
  require_root || return 1

  echo "========================================"
  echo "安全加固（安全默认版）"
  echo "========================================"
  echo "将执行："
  echo "  1. 安装必要依赖（curl/jq/防火墙/fail2ban）"
  echo "  2. 展示并确认 SSH + VPN/Web 端口"
  echo "  3. 备份防火墙状态 → 放行 → 启用（default deny incoming）"
  echo "  4. 安装/配置 Fail2Ban（sshd）"
  echo
  echo "不会执行："
  echo "  - 不会禁用 SSH 密码（请用菜单 6）"
  echo "  - 不会自动放行 3x-ui 面板端口"
  echo "  - 不会删除已有端口规则"
  echo "  - 不会停止 3x-ui / sing-box / Snell / ss-rust"
  echo

  if ! confirm_yes "确认执行？(yes/no): "; then
    log "已取消"
    return 0
  fi

  log "[1/4] 安装依赖..."
  install_dependencies || return 1
  require_jq_if_needed || return 1

  log "[2/4] 端口识别..."
  show_detected_ports
  if ! warn_if_no_node_ports; then
    if ! confirm_yes "确认没有节点端口仍要继续（节点将断）？(yes/no): "; then
      log "已取消"
      return 0
    fi
    if ! confirm_yes "再次确认：将只放行 SSH + 列表项，default deny 其余。继续？(yes/no): "; then
      log "已取消"
      return 0
    fi
  else
    if ! confirm_yes "确认放行上述端口并启用防火墙？（不含 3x-ui 面板）(yes/no): "; then
      log "已取消"
      return 0
    fi
  fi

  log "[3/4] 启用防火墙..."
  # 内联放行逻辑，避免二次完整确认
  _enable_firewall_confirmed || return 1

  log "[4/4] 配置 Fail2Ban..."
  setup_fail2ban_safe || warn "Fail2Ban 配置未完全成功，请手动检查"

  status_report
}

# 供 safe_harden 调用：调用方已完成端口确认
_enable_firewall_confirmed() {
  install_firewall_if_needed || return 1

  local fw fail=0
  fw=$(detect_firewall)
  backup_firewall_state

  log "先放行 SSH..."
  allow_ssh_ports || fail=1

  log "放行 VPN/Web 端口..."
  while IFS=$'\t' read -r port proto name; do
    [ -n "${port:-}" ] || continue
    allow_port "$port" "$proto" "$name" || fail=1
  done < <(sorted_service_ports)

  case "$fw" in
    ufw)
      ufw default deny incoming >/dev/null 2>&1 || warn "default deny incoming 失败"
      ufw default allow outgoing >/dev/null 2>&1 || warn "default allow outgoing 失败"
      ufw default deny routed >/dev/null 2>&1 || true
      if ! ufw --force enable >/dev/null 2>&1; then
        err "ufw enable 失败"
        return 1
      fi
      ufw status verbose
      ;;
    firewalld)
      systemctl enable --now firewalld >/dev/null 2>&1 || true
      if ! firewall-cmd --reload >/dev/null 2>&1; then
        err "firewalld reload 失败"
        return 1
      fi
      firewall-cmd --list-all
      ;;
    *)
      err "未检测到可用防火墙"
      return 1
      ;;
  esac

  if [ "$fail" -ne 0 ]; then
    warn "部分端口放行失败"
    return 1
  fi
  log "防火墙已按清单启用"
  return 0
}

# ---------------------------------------------------------------------------
# 面板白名单 / 手动端口 / dry-run / 日志
# ---------------------------------------------------------------------------

show_version() {
  echo "safety.sh version ${SAFETY_VERSION}"
  echo "备份目录: ${BACKUP_DIR}"
  echo "防火墙后端: $(detect_firewall)"
}

dry_run_report() {
  echo "========================================"
  echo "加固预览（dry-run，不修改系统）"
  echo "========================================"
  echo "版本: ${SAFETY_VERSION}"
  echo "时间: $(date)"
  echo
  show_detected_ports
  echo
  echo "若执行「安全加固 / 启用防火墙」，预计操作："
  echo "  - 备份防火墙状态 → ${BACKUP_DIR}/"
  echo "  - 放行 SSH 端口: $(get_ssh_ports | paste -sd, -)"
  echo "  - 放行以下服务端口（不含 3x-ui 面板）:"
  local lines
  lines=$(sorted_service_ports || true)
  if [ -z "${lines:-}" ]; then
    warn "    （无）— 启用 default deny 后节点可能不可用"
  else
    echo "$lines" | awk -F'\t' '{printf "    allow %s/%s  (%s)\n", $1, $2, $3}'
  fi
  echo "  - ufw: default deny incoming / allow outgoing（若使用 ufw）"
  echo "  - 启用防火墙"
  echo "  - 配置 Fail2Ban sshd jail（若走完整加固）"
  echo
  echo "不会做："
  echo "  - 不开放 3x-ui 面板到 0.0.0.0/0"
  echo "  - 不禁用 SSH 密码"
  echo "  - 不删除已有防火墙规则"
  echo "========================================"
  if ! has_node_ports; then
    err "预览结论：未识别到节点端口，不建议执行加固。"
  else
    log "预览结论：已识别节点端口，可在确认后执行菜单 2 或 3。"
  fi
}

# 3x-ui 面板：仅允许指定源 IP
panel_whitelist_menu() {
  require_root || return 1

  local panel client_ip src_ip fw
  panel=$(detect_xui_panel_port || true)
  client_ip=$(get_current_client_ip || true)
  fw=$(detect_firewall)

  echo "========================================"
  echo "3x-ui 面板 IP 白名单"
  echo "========================================"
  if [ -n "${panel:-}" ]; then
    echo "检测到面板端口: ${panel}/tcp"
  else
    warn "未能自动检测面板端口，可手动输入"
  fi
  if [ -n "${client_ip:-}" ]; then
    echo "当前 SSH 客户端 IP: ${client_ip}"
  fi
  echo "防火墙: ${fw}"
  echo
  echo "说明："
  echo "  - 不会对 0.0.0.0/0 开放面板"
  echo "  - 仅添加 from <你的IP> → panel 端口"
  echo "  - 家庭宽带 IP 变化后需重新执行"
  echo "========================================"
  echo "1. 添加白名单（推荐）"
  echo "2. 查看当前防火墙规则"
  echo "0. 返回"
  local sub
  read -rp "请选择: " sub
  case "$sub" in
    1)
      if [ "$(detect_firewall)" = "none" ]; then
        install_firewall_if_needed || return 1
      fi
      if [ -z "${panel:-}" ]; then
        read -rp "面板端口: " panel
      else
        read -rp "面板端口 [${panel}]: " _p
        [ -n "${_p:-}" ] && panel="$_p"
      fi
      if ! is_valid_port "$panel"; then
        err "端口无效"
        return 1
      fi
      if [ -n "${client_ip:-}" ]; then
        read -rp "允许的源 IP/CIDR [${client_ip}]: " src_ip
        src_ip=${src_ip:-$client_ip}
      else
        read -rp "允许的源 IP/CIDR（例如 203.0.113.10 或 203.0.113.0/24）: " src_ip
      fi
      if ! is_valid_ip "$src_ip"; then
        err "源地址无效"
        return 1
      fi
      echo
      echo "将添加: ${src_ip} → ${panel}/tcp （3x-ui/panel）"
      if ! confirm_yes "确认？(yes/no): "; then
        log "已取消"
        return 0
      fi
      backup_firewall_state
      allow_port_from "$src_ip" "$panel" tcp "3x-ui/panel" || return 1
      case "$(detect_firewall)" in
        ufw) ufw status verbose | head -n 40 ;;
        firewalld) firewall-cmd --list-all ;;
      esac
      log "提示：若防火墙尚未 enable，请先执行菜单 3 启用"
      ;;
    2)
      case "$(detect_firewall)" in
        ufw) ufw status verbose ;;
        firewalld) firewall-cmd --list-rich-rules; firewall-cmd --list-all ;;
        *) echo "未检测到防火墙" ;;
      esac
      ;;
    0) return 0 ;;
    *) err "无效选择" ;;
  esac
}

# 手动补充放行（解析失败或自定义端口时用）
manual_allow_ports() {
  require_root || return 1
  install_firewall_if_needed || return 1

  echo "========================================"
  echo "手动放行端口"
  echo "========================================"
  echo "格式示例："
  echo "  443/tcp"
  echo "  443/udp"
  echo "  8443          （默认 tcp）"
  echo "多端口用空格或逗号分隔。"
  echo "输入空行取消。"
  echo "========================================"
  local line item port proto name fail=0
  read -rp "端口列表: " line
  [ -n "${line:-}" ] || { log "已取消"; return 0; }

  line=${line//,/ }
  backup_firewall_state
  for item in $line; do
    port="${item%%/*}"
    if [[ "$item" == */* ]]; then
      proto="${item##*/}"
    else
      proto="tcp"
    fi
    proto=$(echo "$proto" | tr '[:upper:]' '[:lower:]')
    case "$proto" in
      tcp|udp) ;;
      *) warn "跳过无效协议：$item"; continue ;;
    esac
    name="manual/${port}"
    allow_port "$port" "$proto" "$name" || fail=1
  done

  case "$(detect_firewall)" in
    ufw)
      if ! ufw status 2>/dev/null | grep -qi 'Status: active'; then
        warn "ufw 尚未启用；规则已添加，需菜单 3 或 ufw enable 后生效"
      fi
      ufw status verbose | head -n 50
      ;;
    firewalld)
      firewall-cmd --reload >/dev/null 2>&1 || true
      firewall-cmd --list-all
      ;;
  esac
  [ "$fail" -eq 0 ] || return 1
}

# 日志与近期安全事件
view_logs_menu() {
  while true; do
    echo
    echo "========================================"
    echo "日志查看"
    echo "========================================"
    echo "1. Fail2Ban 状态与日志"
    echo "2. 防火墙规则 / UFW 日志"
    echo "3. SSH / 认证日志（最近失败登录）"
    echo "4. sing-box 服务日志"
    echo "5. 3x-ui / x-ui 服务日志"
    echo "6. 最近安全相关 journal（综合）"
    echo "0. 返回"
    echo "========================================"
    local c
    read -rp "请选择: " c
    case "$c" in
      1) _log_fail2ban ;;
      2) _log_firewall ;;
      3) _log_ssh_auth ;;
      4) _log_unit "sing-box" ;;
      5) _log_unit "x-ui" ; _log_unit "x-ui.service" ;;
      6) _log_security_journal ;;
      0) return 0 ;;
      *) err "无效选择" ;;
    esac
  done
}

_log_tail_file() {
  local f="$1" n="${2:-40}"
  if [ -f "$f" ]; then
    echo "---- $f (last ${n}) ----"
    tail -n "$n" "$f"
  fi
}

_log_fail2ban() {
  echo "---- fail2ban-client status ----"
  fail2ban-client status 2>/dev/null || warn "fail2ban-client 不可用"
  echo
  echo "---- jail: sshd ----"
  fail2ban-client status sshd 2>/dev/null || true
  echo
  if need_cmd journalctl; then
    echo "---- journalctl -u fail2ban (last 40) ----"
    journalctl -u fail2ban -n 40 --no-pager 2>/dev/null || true
  fi
  _log_tail_file /var/log/fail2ban.log 40
}

_log_firewall() {
  case "$(detect_firewall)" in
    ufw)
      echo "---- ufw status verbose ----"
      ufw status verbose 2>/dev/null || true
      echo
      if need_cmd journalctl; then
        echo "---- journalctl UFW (last 30) ----"
        journalctl -k -n 80 --no-pager 2>/dev/null | grep -i ufw | tail -n 30 || true
      fi
      _log_tail_file /var/log/ufw.log 30
      ;;
    firewalld)
      echo "---- firewall-cmd --list-all ----"
      firewall-cmd --list-all 2>/dev/null || true
      echo
      echo "---- rich rules ----"
      firewall-cmd --list-rich-rules 2>/dev/null || true
      echo
      journalctl -u firewalld -n 40 --no-pager 2>/dev/null || true
      ;;
    *)
      warn "未检测到 ufw/firewalld"
      iptables -L -n 2>/dev/null | head -n 40 || true
      ;;
  esac
}

_log_ssh_auth() {
  echo "---- 有效 SSH 配置摘要 ----"
  sshd -T 2>/dev/null | grep -E '^(port|passwordauthentication|permitrootlogin|pubkeyauthentication) ' || true
  echo
  if need_cmd journalctl; then
    echo "---- 最近 SSH 失败/无效用户 (journal, 40 行) ----"
    journalctl -u ssh -u sshd -n 200 --no-pager 2>/dev/null \
      | grep -iE 'Failed|Invalid user|authentication failure|Connection closed' \
      | tail -n 40 || journalctl -u ssh -u sshd -n 40 --no-pager 2>/dev/null || true
  fi
  if [ -f /var/log/auth.log ]; then
    echo "---- /var/log/auth.log 失败登录 ----"
    grep -iE 'Failed password|Invalid user|authentication failure' /var/log/auth.log 2>/dev/null | tail -n 30 || true
  elif [ -f /var/log/secure ]; then
    echo "---- /var/log/secure 失败登录 ----"
    grep -iE 'Failed password|Invalid user|authentication failure' /var/log/secure 2>/dev/null | tail -n 30 || true
  fi
  echo
  echo "---- 最近成功登录 (last -a | head) ----"
  last -a 2>/dev/null | head -n 15 || true
}

_log_unit() {
  local unit="$1"
  if ! need_cmd systemctl; then
    warn "无 systemctl"
    return 0
  fi
  if systemctl cat "$unit" >/dev/null 2>&1 || systemctl status "$unit" >/dev/null 2>&1; then
    echo "---- systemctl status ${unit} ----"
    systemctl status "$unit" --no-pager -l 2>/dev/null | sed -n '1,20p' || true
    echo
    echo "---- journalctl -u ${unit} (last 50) ----"
    journalctl -u "$unit" -n 50 --no-pager 2>/dev/null || true
  else
    warn "未找到 unit: $unit"
  fi
}

_log_security_journal() {
  if ! need_cmd journalctl; then
    warn "无 journalctl"
    return 0
  fi
  echo "---- 综合安全相关日志 (last 60) ----"
  journalctl -n 200 --no-pager 2>/dev/null \
    | grep -iE 'sshd|fail2ban|ufw|firewall| Ban | Unban |INVALID|Failed password' \
    | tail -n 60 || journalctl -n 40 --no-pager 2>/dev/null || true
}

menu() {
  while true; do
    echo
    echo "========================================"
    echo "VPN 服务器安全加固 safety.sh  v${SAFETY_VERSION}"
    echo "========================================"
    echo "1. 查看检测到的服务端口"
    echo "2. 安全加固（推荐，默认不禁 SSH 密码）"
    echo "3. 只启用/修复防火墙放行"
    echo "4. 只安装/修复 Fail2Ban"
    echo "5. SSH 健康检查"
    echo "6. SSH 密钥登录加固（高风险，需二次确认）"
    echo "7. 查看完整安全状态"
    echo "8. 3x-ui 面板 IP 白名单"
    echo "9. 手动放行端口"
    echo "10. 加固预览 dry-run（不改系统）"
    echo "11. 查看日志"
    echo "v. 版本信息"
    echo "0. 退出"
    echo "========================================"
    local choice
    read -rp "请选择 [0-11/v]: " choice

    case "$choice" in
      1) show_detected_ports ;;
      2) safe_harden ;;
      3) enable_firewall_safe ;;
      4) setup_fail2ban_safe ;;
      5) check_ssh_health ;;
      6) ssh_key_only_harden ;;
      7) status_report ;;
      8) panel_whitelist_menu ;;
      9) manual_allow_ports ;;
      10) dry_run_report ;;
      11) view_logs_menu ;;
      v|V) show_version ;;
      0) exit 0 ;;
      *) err "无效选择" ;;
    esac
  done
}

menu
