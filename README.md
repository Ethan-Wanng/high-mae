# wing

wing 是一款面向 Windows 的桌面代理客户端。它集成 sing-box、Mieru Client、本地 HTTP 代理服务与 Web 控制面板，提供节点订阅、测速、规则分流、TUN 接管、DNS 分流、WebRTC 防泄漏和命令行进程规则等能力。

## 核心特性

- 多协议支持：Hysteria2、TUIC、VLESS、VMess、Trojan、Shadowsocks、AnyTLS、Naive、Mieru、HTTP/SOCKS 等。
- 双入口管理：Wails 桌面窗口用于日常操作，系统托盘用于快速切换节点、代理模式、TUN 和退出。
- 本地控制面板：默认运行在 `http://127.0.0.1:10809/`，用于订阅导入、节点管理、测速、规则管理、DNS 管理和流量统计。
- 规则分流：支持域名、域名后缀、域名关键字规则，也支持按命令行完整命令或前缀选择直连/代理。
- TUN 模式：接管不遵循系统代理设置的应用流量；需要管理员权限。
- DNS 分流：支持本地 DNS 服务和按域名规则选择 DNS 服务器。
- 隐私辅助：提供 WebRTC 防泄漏策略和连接日志隐私模式。

## 命令行规则说明

命令行进程规则用于本地 HTTP 代理入口收到连接时，根据发起连接的进程命令行改写路由动作。默认预设：

```text
go test -> 直连
```

该能力适用于会连接本地 HTTP 代理的 TCP 请求，例如浏览器、`curl -x http://127.0.0.1:10808 ...`、Go 模块下载等。

`ping` 使用 ICMP，不会进入本地 HTTP 代理，因此不能用 `ping youtube.com` 验证命令行规则是否生效。需要接管这类流量时请使用 TUN 模式。

## 技术架构

- 桌面框架：Wails v2
- 托盘菜单：getlantern/systray
- 代理核心：sing-box 与项目内适配层
- Mieru 支持：Mieru Client API
- 控制面板：Go 标准库 `net/http` + 内置静态页面
- 存储：bbolt 与本地配置文件迁移兼容
- 网络接管：Wintun + tun2socks

## 快速开始

### 运行环境

- Windows 10/11
- 管理员权限：仅开启 TUN、系统 DNS 覆写或部分系统策略时需要

### 使用方式

1. 运行 `wing.exe`。
2. 在桌面窗口或托盘菜单中打开控制面板。
3. 导入订阅链接或节点分享链接。
4. 选择节点并开启系统代理；需要接管更多应用流量时开启 TUN。
5. 在规则管理中配置域名规则或命令行进程规则。

### 本地构建

```powershell
go mod download
./scripts/mk.ps1
```

## 开源协议

本项目采用 MIT 协议开源。第三方依赖遵循其各自许可证。

---

Created by Ethan-Wanng
