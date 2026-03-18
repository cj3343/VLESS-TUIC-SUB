# VPN 节点一键安装脚本
我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！我自己用的！！
一键安装和管理 Sing-box（VLESS-Reality + TUIC）和 Snell 代理节点的 Shell 脚本。

## 功能特性

### Sing-box 支持
- ✅ VLESS-Reality 协议（抗审查能力强）
- ✅ TUIC v5 协议（基于 QUIC，低延迟）
- ✅ 自动域名测速选择最优 Reality 伪装域名
- ✅ 自动生成分享链接和二维码
- ✅ BBR 加速自动启用
- ✅ 完整的诊断和故障排查工具

### Snell 支持
- ✅ Snell v4 协议（Surge 专用）
- ✅ 自动生成 Surge 配置
- ✅ 支持 TCP Fast Open、连接复用、ECN
- ✅ 自动架构检测（amd64/aarch64）
- ✅ 备用下载源（主源失败自动切换）
- ✅ 完整的连接诊断功能

## 系统要求

- **操作系统**: Ubuntu 20.04+, Debian 10+, CentOS 7+
- **架构**: x86_64 (amd64) 或 ARM64 (aarch64)
- **权限**: root 用户
- **网络**: 需要访问 GitHub 和相关下载源

## 快速开始

### 一键安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/cj3343/VLESS-TUIC-SUB/main/setup.sh)
```

或者下载后运行：

```bash
wget https://raw.githubusercontent.com/cj3343/VLESS-TUIC-SUB/main/setup.sh
chmod +x setup.sh
bash setup.sh
```

### 3. 选择功能

脚本会显示交互式菜单，根据需要选择对应功能。

## 项目地址

GitHub: [https://github.com/cj3343/VLESS-TUIC-SUB](https://github.com/cj3343/VLESS-TUIC-SUB)

## 菜单功能说明

### Sing-box 管理（选项 1-11）

| 选项 | 功能 | 说明 |
|------|------|------|
| 1 | 全新安装 Sing-box | 首次安装推荐使用 |
| 2 | 清理后重新安装 | 保留备份，重新安装 |
| 3 | 仅清理配置 | 不安装，只清理 |
| 4 | 卸载 sing-box | 完全卸载并备份配置 |
| 5 | 查看当前配置 | 显示节点信息和服务状态 |
| 6 | 诊断连接问题 | 全面诊断网络和配置问题 |
| 7 | 彻底清理并重装 | 完全重置，不保留任何数据 |
| 8 | 查询 Reality 域名 | 查看当前使用的伪装域名 |
| 9 | 修改 Reality 域名 | 更换伪装域名 |
| 10 | 综合检查 | 检查安装完整性 |
| 11 | 重新加载节点信息 | 重新生成分享链接和二维码 |

### Snell 管理（选项 12-17）

| 选项 | 功能 | 说明 |
|------|------|------|
| 12 | 安装 Snell 节点 | 安装 Snell v4 服务 |
| 13 | 查看 Snell 配置 | 显示 Surge 配置和服务状态 |
| 14 | 卸载 Snell | 完全卸载并备份配置 |
| 15 | 重启 Snell 服务 | 重启服务 |
| 16 | 重新生成配置 | 重新生成 Surge 配置（不重装） |
| 17 | 诊断连接问题 | 全面诊断 Snell 连接问题 |

## 使用示例

### 安装 Sing-box

```bash
bash setup.sh
# 选择 1（全新安装）
# 按提示输入端口（或使用默认值）
# 等待安装完成
# 复制生成的分享链接到客户端
```

### 安装 Snell

```bash
bash setup.sh
# 选择 12（安装 Snell）
# 按提示输入端口（或使用默认值）
# 复制生成的 Surge 配置行
# 粘贴到 Surge 配置文件
```

### 诊断连接问题

```bash
bash setup.sh
# Sing-box: 选择 6
# Snell: 选择 17
# 查看诊断结果，按提示修复
```

## 配置文件位置

### Sing-box
- 配置文件: `/etc/sing-box/config.json`
- 分享链接: `/etc/sing-box/share-links.txt`
- Reality 密钥: `/etc/sing-box/reality.txt`
- TUIC 证书: `/etc/sing-box/tuic.crt` 和 `/etc/sing-box/tuic.key`

### Snell
- 配置文件: `/etc/snell/snell-server.conf`
- Surge 配置: `/etc/snell/config.txt`
- 版本信息: `/etc/snell/ver.txt`

## 客户端配置

### Sing-box 客户端

**支持的客户端:**
- Android: NekoBox, v2rayNG
- iOS: Shadowrocket
- Windows/macOS: sing-box, v2rayN, Clash Verge

**导入方式:**
1. 扫描脚本生成的二维码
2. 或复制分享链接手动导入

### Snell 客户端

**支持的客户端:**
- iOS/macOS: Surge

**Surge 配置格式:**
```
[Proxy]
节点名 = snell, 服务器IP, 端口, psk=密钥, version=4, tfo=true, reuse=true, ecn=true
```

## 常见问题

### 1. 无法连接节点

**可能原因:**
- 云服务商安全组未开放端口（最常见）
- 系统防火墙未开放端口
- 配置格式错误
- 客户端版本过旧

**解决方法:**
1. 运行诊断功能（菜单 6 或 17）
2. 检查云服务商安全组规则
3. 开放系统防火墙端口
4. 验证配置格式

### 2. Sing-box DNS 配置错误

**错误信息:**
```
ERROR[0000] legacy DNS servers is deprecated in sing-box 1.12.0
```

**解决方法:**
本脚本已修复此问题，使用新版 DNS 格式。如果仍有问题，重新运行安装。

### 3. Snell 服务启动失败

**可能原因:**
- 缺少 unzip 工具
- 下载失败
- 端口被占用

**解决方法:**
脚本会自动安装依赖并使用备用下载源。如果失败，查看日志：
```bash
journalctl -u snell -n 50
```

### 4. 端口被占用

**检查端口占用:**
```bash
ss -tulnp | grep <端口>
```

**更换端口:**
- Sing-box: 编辑 `/etc/sing-box/config.json`，修改 `listen_port`
- Snell: 编辑 `/etc/snell/snell-server.conf`，修改 `listen`

然后重启服务：
```bash
systemctl restart sing-box  # 或 snell
```

## 防火墙配置

### Ubuntu/Debian (ufw)

```bash
# Sing-box
ufw allow 443/tcp   # VLESS
ufw allow 8443/udp  # TUIC

# Snell
ufw allow <端口>/tcp
```

### CentOS/RHEL (firewalld)

```bash
# Sing-box
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --permanent --add-port=8443/udp

# Snell
firewall-cmd --permanent --add-port=<端口>/tcp

firewall-cmd --reload
```

### 云服务商安全组

**AWS EC2:**
1. EC2 控制台 → 实例 → 安全组
2. 编辑入站规则
3. 添加规则：协议 TCP/UDP，端口，来源 0.0.0.0/0

**阿里云/腾讯云:**
1. 实例管理 → 安全组
2. 添加入站规则
3. 协议类型：TCP/UDP，端口范围，授权对象 0.0.0.0/0

## 服务管理

### 查看服务状态

```bash
systemctl status sing-box
systemctl status snell
```

### 启动/停止/重启服务

```bash
systemctl start sing-box
systemctl stop sing-box
systemctl restart sing-box

systemctl start snell
systemctl stop snell
systemctl restart snell
```

### 查看日志

```bash
journalctl -u sing-box -f
journalctl -u snell -f
```

### 开机自启

```bash
systemctl enable sing-box
systemctl enable snell
```

## 卸载

### 卸载 Sing-box

```bash
bash setup.sh
# 选择 4（卸载 sing-box）
# 配置会自动备份到 /root/
```

### 卸载 Snell

```bash
bash setup.sh
# 选择 14（卸载 Snell）
# 配置会自动备份到 /root/
```

## 安全建议

1. **定期更新系统**
   ```bash
   apt update && apt upgrade -y  # Ubuntu/Debian
   yum update -y                 # CentOS/RHEL
   ```

2. **修改 SSH 端口**
   ```bash
   # 编辑 /etc/ssh/sshd_config
   Port 2222
   systemctl restart sshd
   ```

3. **禁用密码登录，只用密钥**
   ```bash
   # 编辑 /etc/ssh/sshd_config
   PasswordAuthentication no
   ```

4. **定期更改密钥**
   - 重新运行安装脚本会生成新的 UUID/PSK

5. **不要分享配置给不信任的人**

6. **监控流量使用**
   ```bash
   apt install vnstat
   vnstat -l
   ```

## 技术细节

### Sing-box 配置

- **VLESS-Reality**: 使用 TLS 指纹伪装，抗主动探测
- **TUIC v5**: 基于 QUIC 协议，UDP 传输，低延迟
- **DNS**: 使用 Cloudflare DNS (1.1.1.1)
- **BBR**: 自动启用 TCP BBR 拥塞控制算法

### Snell 配置

- **版本**: Snell v4.1.1
- **协议**: Snell v4 协议
- **特性**: TCP Fast Open, 连接复用, ECN
- **监听**: IPv4 + IPv6 双栈

## 故障排查

### 使用诊断工具

脚本内置了完整的诊断功能：

```bash
bash setup.sh
# Sing-box: 选择 6
# Snell: 选择 17
```

诊断工具会检查：
- ✅ 服务状态
- ✅ 配置文件
- ✅ 端口监听
- ✅ 防火墙规则
- ✅ 服务日志
- ✅ 本地连接
- ✅ 公网 IP
- ✅ 配置格式

### 手动测试端口连通性

**在本地电脑测试:**

```bash
# macOS/Linux
nc -zv <服务器IP> <端口>

# Windows PowerShell
Test-NetConnection -ComputerName <服务器IP> -Port <端口>
```

### 查看详细日志

```bash
# 实时日志
journalctl -u sing-box -f
journalctl -u snell -f

# 最近 50 行
journalctl -u sing-box -n 50
journalctl -u snell -n 50
```

## 更新日志

### v2.0 (2026-03-16)
- ✅ 修复 sing-box 1.12.0+ DNS 配置格式问题
- ✅ 集成 Snell v4 安装和管理
- ✅ 添加完整的诊断功能
- ✅ 优化错误处理和依赖检查
- ✅ 添加备用下载源
- ✅ 改进 Surge 配置格式

### v1.0
- ✅ 初始版本
- ✅ Sing-box VLESS-Reality + TUIC 支持

## 许可证

MIT License

## 免责声明
我自己用的！！

**注意**: 请遵守当地法律法规，合理使用代理工具。
