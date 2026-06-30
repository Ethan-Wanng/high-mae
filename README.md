<p align="center">
  <img src="pkg/webui/ui/logo-mark-app.png" width="148" alt="wing 彩色渐变软件图标">
</p>

<h1 align="center">wing</h1>

<p align="center">
  <img src="pkg/webui/ui/logo-mark-direct-light.png" width="54" alt="浅色直连图标">
  <img src="pkg/webui/ui/logo-mark-direct-dark.png" width="54" alt="深色直连图标">
  <img src="pkg/webui/ui/logo-mark-proxy.png" width="54" alt="代理模式图标">
  <img src="pkg/webui/ui/logo-mark-tun.png" width="54" alt="TUN 模式图标">
  <img src="pkg/webui/ui/logo-mark-proxy-tun.png" width="54" alt="代理加 TUN 模式图标">
</p>

wing 是一款基于 Flutter + Go 的跨平台代理客户端。它集成 sing-box、Mieru Client、本地 HTTP 代理服务与 Web 控制面板，把节点订阅、测速、网站可用性测试、自动选点、规则分流、隧道连接、DNS 分流、WebRTC 防泄漏和命令行进程规则收进一个轻量桌面入口。界面采用扁平化布局，随网络状态切换直连、代理、TUN、代理 + TUN 四套配色；安装包、桌面窗口和搜索入口使用彩色渐变 wing 图标，首页、自动选择入口和托盘图标会按当前模式自动换成对应图标。

## 核心特性

- 多协议支持：Hysteria2、TUIC、VLESS、VMess、Trojan、Shadowsocks、AnyTLS、Naive、Mieru、HTTP/SOCKS 等。
- 多入口管理：Flutter 桌面窗口启动后自动显示，Go 系统托盘用于再次唤起窗口、快速切换代理模式、隧道连接和退出；Android/iOS Flutter 壳用于访问本机、模拟器或局域网控制面板。
- 灵动岛导航：默认以收缩胶囊呈现，鼠标悬停后展开为纯图标标签；当前网络状态会改变界面配色，首屏以居中的节点入口卡片作为默认操作入口。
- 本地控制面板：默认运行在 `http://127.0.0.1:10809/`，用于订阅导入、节点管理、测速、网站测试、规则管理、DNS 管理和流量统计。
- 订阅管理：支持为订阅设置自动更新时间间隔，并优化远程订阅更新速度。
- 免费流量：内置获取免费流量入口，按周限制可用流量，用完后自动停止使用该入口。
- 延迟测速：支持单节点、订阅组和聚合组测速；展开订阅组或聚合组时会自动测试组内节点延迟。
- 自动选点：支持全节点、指定订阅组和指定聚合组范围内按延迟自动选择节点；开启后按用户设置的间隔自动重测候选节点并选择一次，也支持手动立即选择。
- 自动选点规则：用户可编辑排除关键字、只选地区、只选节点、只选订阅组、只选聚合组、使用/不使用协议和网站可用性规则；默认提供可删除的“不使用香港的节点”规则。
- 网站可用性测试：可检测当前节点对 ChatGPT、Gemini、Claude、TikTok、YouTube、Netflix、BBC News、ESPN 等网站的支持情况，支持一键全量测试和单点测试，也支持添加自定义测试网站。
- 规则分流：支持域名、域名后缀、域名关键字规则，也支持按命令行完整命令或前缀选择直连/代理。
- 隧道连接：基于内置 sing-box TUN + Wintun 接管不遵循系统代理设置的应用流量；需要管理员权限。
- DNS 分流：支持本地 DNS 服务和按域名规则选择 DNS 服务器。
- 隐私辅助：提供 WebRTC 防泄漏策略和连接日志隐私模式，订阅、DNS、路由、自动选择和聚合组等本地配置会通过项目安全存储层读写。
- 五平台发布：Release workflow 会生成 Windows、macOS、Linux、Android 和 iOS 产物；Windows 默认使用标准 Inno Setup 安装包，降低安全软件误报概率。

## 命令行规则说明

命令行进程规则用于本地 HTTP 代理入口收到连接时，根据发起连接的进程命令行改写路由动作。默认预设：

```text
go test -> 直连
```

该能力适用于会连接本地 HTTP 代理的 TCP 请求，例如浏览器、`curl -x http://127.0.0.1:10808 ...`、Go 模块下载等。

`ping` 使用 ICMP，不会进入本地 HTTP 代理，因此不能用 `ping youtube.com` 验证命令行规则是否生效。需要接管这类流量时请使用 TUN 模式。

## 帮助中心

### 网络状态颜色

浅色主题会按当前连接状态切换背景色：直连为白色，代理为浅蓝色，TUN 为浅黄色，代理 + TUN 为浅紫色。文字颜色会随背景一起调整，避免浅色背景下看不清。

### 图标对应关系

安装包、桌面快捷方式、开始菜单和窗口右上角使用彩色渐变 wing 图标。运行时图标会跟随模式切换：浅色直连使用黑灰 wing，深色直连使用白色 wing，代理模式使用蓝色 wing，TUN 模式使用黄色 wing，代理 + TUN 模式使用紫色 wing。首页、自动选择和系统托盘保持同一套映射。

### 安装后没有图标

Windows 有时会缓存旧快捷方式图标。标准安装包会把 `icon.ico` 安装到程序目录，并让开始菜单、桌面快捷方式和卸载项显式使用它；如果搜索结果仍显示旧图标，可退出 wing 后重新安装，或删除旧的开始菜单快捷方式后再安装一次。

### 开启 TUN 提示权限

TUN 会接管不遵循系统代理的应用流量，因此需要管理员权限安装或调用相关网络能力。普通系统代理、节点管理、测速和网站可用性测试不需要管理员权限。

### 控制面板打不开

确认 `wing.exe` 正在运行，并访问 `http://127.0.0.1:10809/`。如果端口被占用或安全软件拦截，请退出占用端口的程序后重启 wing。

## 技术架构

- 桌面框架：Flutter Desktop + Windows WebView2
- 移动端壳：Flutter + webview_flutter
- 后端进程：Go 常驻服务与系统托盘
- 托盘菜单：getlantern/systray
- 代理核心：sing-box 与项目内适配层
- Mieru 支持：Mieru Client API
- 控制面板：Flutter WebView 承载 Go 标准库 `net/http` 内置静态页面
- 存储：bbolt、本地配置迁移兼容与安全存储封装
- 网络接管：内置 sing-box TUN + Wintun

## 快速开始

### 运行环境

- Windows 10/11、macOS、Linux、Android 或 iOS
- Flutter 3.29.2 或兼容版本
- Go 1.25.0 或兼容版本
- Visual Studio 2022 Build Tools，需安装 “Desktop development with C++” 工作负载，用于构建 Flutter Windows 桌面应用
- Inno Setup 6：使用 `./scripts/mk.ps1 package` 或 `installer` 生成 Windows 标准安装包时需要
- 管理员权限：仅开启 TUN、系统 DNS 覆写或部分系统策略时需要

### 使用方式

1. 运行 `wing.exe`。
2. 桌面控制面板会自动显示；也可以通过托盘菜单再次唤起。
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

双击根目录的 `package-wing.bat` 可以构建并生成给最终用户使用的 Windows 标准安装包：

```text
dist/wing-1.0.5-windows-x64-setup.exe
```

命令行方式如下：

```powershell
./scripts/mk.ps1 build  # 构建 Flutter 控制面板与 Go 后端
./scripts/mk.ps1 package # 构建并生成 dist/wing-1.0.5-windows-x64-setup.exe 标准安装包
./scripts/mk.ps1 installer # 同 package
./scripts/mk.ps1 portable # 生成旧版自解压安装包，不建议作为公开 Release 资产
./scripts/mk.ps1 backend # 仅构建 Go 后端
./scripts/mk.ps1 run    # 构建 Flutter 控制面板后直接运行 Go 后端
./scripts/mk.ps1 test   # 运行 Go 测试
./scripts/mk.ps1 ui     # 仅构建 Flutter 控制面板
./scripts/mk.ps1 inno   # 使用 Inno Setup 生成标准安装包
```

构建产物：

- `wing.exe`：Go 后端、系统托盘、本地代理与本地 Web API。
- `build/bin/flutter_ui/wing_ui.exe`：Flutter 桌面控制面板，会加载 `http://127.0.0.1:10809/`。
- `dist/wing-1.0.5-windows-x64-setup.exe`：标准 Windows 安装包，用户双击后可选择安装目录。
- `dist/wing-installer.exe`：旧版自解压安装器，仅通过 `portable` 命令生成，公开分发时不推荐使用。

### 其他平台打包

以下脚本会在不满足平台条件时直接失败并给出原因，避免生成不可安装的伪产物：

```bash
# Linux: 需在 Linux 上执行，生成用户态 .run 安装器
bash scripts/package-linux.sh

# macOS: 需在 macOS 上执行，生成 /Applications/wing.app 的 pkg
bash scripts/package-macos.sh

# Android: 需配置 Flutter + Android SDK，生成可安装 APK
bash scripts/package-android.sh

# iOS: 需在 macOS + Xcode 上执行
# 未配置签名时生成 unsigned IPA；配置 IOS_EXPORT_OPTIONS_PLIST 后生成可安装签名 IPA
bash scripts/package-ios.sh
```

可通过环境变量覆盖版本与构建号：

```bash
WING_VERSION=1.0.5 FLUTTER_BUILD_NUMBER=1005 bash scripts/package-android.sh
```

### Release 资产

GitHub Actions 的 `release.yml` 会为 `v*` 标签生成并上传以下资产：

- `wing-1.0.5-windows-x64-setup.exe`
- `wing-1.0.5-linux-x64.run`
- `wing-1.0.5-macos-x64.pkg`
- `wing-1.0.5-android-universal.apk`
- `wing-1.0.5-ios-unsigned.ipa`

iOS 默认 Release 资产是未签名 IPA，需要 Apple Developer 证书签名后才能真机分发；本地可通过 `IOS_EXPORT_OPTIONS_PLIST=/path/to/ExportOptions.plist bash scripts/package-ios.sh` 生成签名 IPA。Windows 代理软件未签名时仍可能被部分安全软件误报；仓库提供 `scripts/sign-windows.ps1`，在配置代码签名证书后可自动签名 Windows 可执行文件和安装包。

## 安全与隐私

- 控制面板默认只监听 `127.0.0.1:10809`，不会默认暴露到局域网。
- Web UI API 要求本地可信 Origin 与 `X-Wing-Request` 请求头，降低跨站调用风险。
- 移动端 WebView 只允许打开 localhost、Android 模拟器地址和私有局域网地址。
- DNS 泄漏防护、WebRTC 防泄漏、系统 DNS 覆写和 TUN 接管均需要用户显式开启或确认。
- 节点、订阅和网络配置属于敏感信息，公开 issue 或日志时请先脱敏。

## 开源协议

本项目采用 MIT 协议开源。第三方依赖遵循其各自许可证。

---

Created by Ethan-Wanng
