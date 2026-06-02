# wing

wing 是一款桌面代理客户端。它集成 sing-box、Mieru Client、本地 HTTP 代理服务与 Web 控制面板，提供节点订阅、测速、网站可用性测试、自动选点、规则分流、隧道连接、DNS 分流、WebRTC 防泄漏和命令行进程规则等能力。

## 核心特性

- 多协议支持：Hysteria2、TUIC、VLESS、VMess、Trojan、Shadowsocks、AnyTLS、Naive、Mieru、HTTP/SOCKS 等。
- 双入口管理：Flutter 桌面窗口用于日常操作，Go 系统托盘用于快速切换节点、代理模式、隧道连接和退出。
- 本地控制面板：默认运行在 `http://127.0.0.1:10809/`，用于订阅导入、节点管理、测速、网站测试、规则管理、DNS 管理和流量统计。
- 订阅管理：支持为订阅设置自动更新时间间隔，并优化远程订阅更新速度。
- 免费流量：内置获取免费流量入口，按周限制可用流量，用完后自动停止使用该入口。
- 延迟测速：支持单节点、订阅组和聚合组测速；展开订阅组或聚合组时会自动测试组内节点延迟。
- 自动选点：支持全节点、指定订阅组和指定聚合组范围内按延迟自动选择节点；开启后按用户设置的间隔自动重测候选节点并选择一次，可选择自动启动系统代理或 TUN，也支持手动立即选择。
- 自动选点规则：用户可编辑排除关键字、只选地区、只选节点、只选订阅组、只选聚合组、使用/不使用协议和网站可用性规则；默认提供可删除的“不使用香港的节点”规则。
- 网站可用性测试：可检测当前节点对 ChatGPT、Gemini、Claude、TikTok、YouTube、Netflix、BBC News、ESPN 等网站的支持情况，支持一键全量测试和单点测试，也支持添加自定义测试网站。
- 规则分流：支持域名、域名后缀、域名关键字规则，也支持按命令行完整命令或前缀选择直连/代理。
- 隧道连接：基于内置 sing-box TUN + Wintun 接管不遵循系统代理设置的应用流量；需要管理员权限。
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

- 桌面框架：Flutter Desktop + Windows WebView2
- 后端进程：Go 常驻服务与系统托盘
- 托盘菜单：getlantern/systray
- 代理核心：sing-box 与项目内适配层
- Mieru 支持：Mieru Client API
- 控制面板：Flutter WebView 承载 Go 标准库 `net/http` 内置静态页面
- 存储：bbolt 与本地配置文件迁移兼容
- 网络接管：内置 sing-box TUN + Wintun

## 快速开始

### 运行环境

- Windows 10/11、macOS 或 Linux
- Flutter 3.29.2 或兼容版本
- Go 1.25.0 或兼容版本
- Visual Studio 2022 Build Tools，需安装 “Desktop development with C++” 工作负载，用于构建 Flutter Windows 桌面应用
- Inno Setup 6：可选，仅在使用 `./scripts/mk.ps1 inno` 生成传统安装向导时需要
- 管理员权限：仅开启 TUN、系统 DNS 覆写或部分系统策略时需要

### 使用方式

1. 运行 `wing.exe`。
2. 在桌面窗口或托盘菜单中打开控制面板。
3. 导入订阅链接或节点分享链接。
4. 选择节点并开启系统代理；需要接管更多应用流量时开启隧道连接。
5. 在网站测试中检查当前节点对常用网站的支持情况。
6. 在节点选择的自动选择标签中按需开启自动选点，并维护自动选点过滤规则。
7. 在规则管理中配置域名规则或命令行进程规则。

### 本地构建

```powershell
go mod download
./scripts/mk.ps1 build
```

常用构建命令：

双击根目录的 `build-wing.bat` 可以一键构建 Flutter 控制面板与 Go 后端。

双击根目录的 `package-wing.bat` 可以构建并生成给最终用户使用的单文件安装包：

```text
dist/wing-installer.exe
```

命令行方式如下：

```powershell
./scripts/mk.ps1 build  # 构建 Flutter 控制面板与 Go 后端
./scripts/mk.ps1 package # 构建并生成 dist/wing-installer.exe 单文件安装包
./scripts/mk.ps1 backend # 仅构建 Go 后端
./scripts/mk.ps1 run    # 构建 Flutter 控制面板后直接运行 Go 后端
./scripts/mk.ps1 test   # 运行 Go 测试
./scripts/mk.ps1 ui     # 仅构建 Flutter 控制面板
./scripts/mk.ps1 inno   # 可选：使用 Inno Setup 生成 dist/wing-setup.exe
```

构建产物：

- `wing.exe`：Go 后端、系统托盘、本地代理与本地 Web API。
- `build/bin/flutter_ui/wing_ui.exe`：Flutter 桌面控制面板，会加载 `http://127.0.0.1:10809/`。
- `dist/wing-installer.exe`：单文件安装器，用户双击后可选择安装目录。
- `dist/wing-setup.exe`：可选的 Inno Setup 安装包。

## 开源协议

本项目采用 MIT 协议开源。第三方依赖遵循其各自许可证。

---

Created by Ethan-Wanng
