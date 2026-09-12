# iOS 独立应用：描述文件安装准备（尚不可作为 VPN 使用）

iOS 版本使用 `NetworkExtension` 的 Packet Tunnel，而不是 WebView 或远程控制面板。开发安装需要 Apple Developer 账号开启 Network Extensions capability，并为主应用和 Packet Tunnel Extension 分别创建 App ID 与描述文件。

当前 `codex/native-ios` 是工程及签名链的开发分支。Packet Tunnel 的 `packetFlow` 尚未连接到代理核心，连接会明确失败，避免显示“已连接”却断网。**不要将 CI 的无签名 IPA 或当前签名包作为可用 VPN 分发。** 完成数据包转发并在真机验证后才可安装用于日常网络连接。

建议标识：

- 主应用：`com.highmae.wing`
- VPN 扩展：`com.highmae.wing.PacketTunnel`
- App Group：`group.com.highmae.wing`

在 macOS 上准备开发证书导出的 `.p12`，以及主应用、VPN 扩展各自的 `.mobileprovision` 后运行：

```bash
IOS_PROVISIONING_PROFILE=/secure/wing.mobileprovision \
IOS_PACKET_TUNNEL_PROVISIONING_PROFILE=/secure/wing-tunnel.mobileprovision \
IOS_P12_PATH=/secure/development.p12 \
IOS_P12_PASSWORD='***' \
IOS_TEAM_ID=ABCDE12345 \
IOS_BUNDLE_ID=com.highmae.wing \
bash scripts/package-ios-profile.sh
```

签名链打通后 IPA 位于 `dist/wing-1.0.6.2-ios.ipa`，可通过 Xcode Devices and Simulators、Apple Configurator 或受信任的 MDM 安装。设备 UDID 必须包含在 development/ad-hoc 描述文件中。

不要把 `.p12`、密码或 `.mobileprovision` 提交到仓库。Packet Tunnel entitlement 必须由 Apple 开发者后台实际授权；普通个人免费签名无法启用该能力。
