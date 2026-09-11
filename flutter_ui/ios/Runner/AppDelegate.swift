import Flutter
import NetworkExtension
import UIKit
import WingCore

@main
@objc class AppDelegate: FlutterAppDelegate {
  private let channelName = "com.highmae.wing/vpn"
  private let tokenKey = "wing.mobile.api.token"

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)
    guard let controller = window?.rootViewController as? FlutterViewController else {
      return super.application(application, didFinishLaunchingWithOptions: launchOptions)
    }
    FlutterMethodChannel(name: channelName, binaryMessenger: controller.binaryMessenger)
      .setMethodCallHandler { [weak self] call, result in
        self?.handle(call, result: result)
      }
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "startBackend":
      let token = mobileToken()
      let error = IosbridgeStart(applicationSupportDirectory(), token)
      result(["ready": error.isEmpty, "token": token,
              "error": error.isEmpty ? NSNull() : error, "abi": "arm64"])
    case "getVpnStatus":
      withManager { manager, _ in
        let status = manager?.connection.status
        result(status == .connected || status == .connecting || status == .reasserting)
      }
    case "startVpn":
      configureAndStartTunnel(result: result)
    case "stopVpn":
      withManager { manager, error in
        guard error == nil else {
          result(FlutterError(code: "VPN_LOAD_FAILED", message: error?.localizedDescription, details: nil))
          return
        }
        manager?.connection.stopVPNTunnel()
        result(true)
      }
    case "shareText":
      let arguments = call.arguments as? [String: Any]
      let text = arguments?["text"] as? String ?? ""
      let share = UIActivityViewController(activityItems: [text], applicationActivities: nil)
      window?.rootViewController?.present(share, animated: true)
      result(true)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func configureAndStartTunnel(result: @escaping FlutterResult) {
    withManager { manager, error in
      guard error == nil else {
        result(FlutterError(code: "VPN_LOAD_FAILED", message: error?.localizedDescription, details: nil))
        return
      }
      let target = manager ?? NETunnelProviderManager()
      let proto = NETunnelProviderProtocol()
      proto.providerBundleIdentifier = "\(Bundle.main.bundleIdentifier!).PacketTunnel"
      proto.serverAddress = "wing"
      target.protocolConfiguration = proto
      target.localizedDescription = "wing"
      target.isEnabled = true
      target.saveToPreferences { saveError in
        guard saveError == nil else {
          result(FlutterError(code: "VPN_SAVE_FAILED", message: saveError?.localizedDescription, details: nil))
          return
        }
        target.loadFromPreferences { loadError in
          do {
            if let loadError { throw loadError }
            try target.connection.startVPNTunnel()
            result(true)
          } catch {
            result(FlutterError(code: "VPN_START_FAILED", message: error.localizedDescription, details: nil))
          }
        }
      }
    }
  }

  private func withManager(_ completion: @escaping (NETunnelProviderManager?, Error?) -> Void) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
      completion(managers?.first, error)
    }
  }

  private func mobileToken() -> String {
    if let token = UserDefaults.standard.string(forKey: tokenKey), !token.isEmpty { return token }
    let token = UUID().uuidString + UUID().uuidString
    UserDefaults.standard.set(token, forKey: tokenKey)
    return token
  }

  private func applicationSupportDirectory() -> String {
    let url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url.path
  }
}
