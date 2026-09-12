import NetworkExtension
import os.log

/// Native iOS packet-tunnel entry point. The proxy core framework owns packet
/// processing; this class owns the Apple VPN lifecycle and network settings.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "com.highmae.wing", category: "PacketTunnel")

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "172.19.0.1")
        settings.mtu = 1500
        settings.ipv4Settings = NEIPv4Settings(
            addresses: ["172.19.0.1"],
            subnetMasks: ["255.255.255.252"]
        )
        settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        settings.ipv6Settings = NEIPv6Settings(
            addresses: ["fdfe:dcba:9876::1"],
            networkPrefixLengths: [126]
        )
        settings.ipv6Settings?.includedRoutes = [NEIPv6Route.default()]
        settings.dnsSettings = NEDNSSettings(servers: ["172.19.0.2"])

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard error == nil else {
                completionHandler(error)
                return
            }
            self?.logger.info("wing packet tunnel network settings installed")
            // The packetFlow-to-core bridge is not implemented yet. Do not
            // report a connected tunnel that would blackhole device traffic.
            let unavailable = NSError(
                domain: "com.highmae.wing.PacketTunnel",
                code: 1001,
                userInfo: [NSLocalizedDescriptionKey: "wing iOS packet processing is not ready"]
            )
            completionHandler(unavailable)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        logger.info("wing packet tunnel stopped, reason: \(reason.rawValue)")
        completionHandler()
    }
}
