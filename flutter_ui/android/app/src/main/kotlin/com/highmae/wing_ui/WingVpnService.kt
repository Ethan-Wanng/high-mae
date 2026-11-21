package com.highmae.wing_ui

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileDescriptor
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

class WingVpnService : VpnService() {

    companion object {
        const val TAG = "WingVpnService"
        const val ACTION_START = "com.highmae.wing_ui.START_VPN"
        const val ACTION_STOP = "com.highmae.wing_ui.STOP_VPN"
        const val ACTION_RECONNECT = "com.highmae.wing_ui.RECONNECT_VPN"
        const val CHANNEL_ID = "wing_vpn_channel"
        const val NOTIFICATION_ID = 10809
        const val ABSTRACT_SOCKET_NAME = "wing_vpn_fd"

        private const val CMD_STOP = 0
        private const val CMD_START = 1
        private const val CMD_NETWORK_CHANGED = 2

        @Volatile
        var isRunning = false
            private set

        @Volatile
        var isStarting = false
            private set

        @Volatile
        var lastError: String? = null
            private set

        fun prepareForStart() {
            lastError = null
        }
    }

    private val vpnLock = Any()
    private val vpnGeneration = AtomicInteger(0)
    private val netChangeSequence = AtomicInteger(0)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val availableNetworks = LinkedHashMap<String, Network>()
    private var lastNotifiedNetworkId: String? = null
    private var watchdogGeneration: Int = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            if (WingBackendManager.isVpnDesired(this) && VpnService.prepare(this) == null) {
                enterForeground(isRunning)
                startVpn()
                return START_STICKY
            }
            leaveForeground()
            stopSelf()
            return START_NOT_STICKY
        }

        when (intent.action ?: ACTION_START) {
            ACTION_START -> {
                WingBackendManager.setVpnDesired(this, true)
                enterForeground(isRunning)
                startVpn()
                return START_STICKY
            }
            ACTION_STOP -> {
                WingBackendManager.setVpnDesired(this, false)
                stopVpn()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RECONNECT -> {
                enterForeground(isRunning)
                reconnectBackend()
                return START_STICKY
            }
            else -> return START_STICKY
        }
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        // Keep foreground VPN service alive when swiped away from recents if VPN is active.
    }

    private fun enterForeground(connected: Boolean) {
        createNotificationChannel()
        val notification = createNotification(connected)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun leaveForeground() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun notifyState(connected: Boolean) {
        try {
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.notify(NOTIFICATION_ID, createNotification(connected))
        } catch (e: Exception) {
            Log.w(TAG, "Failed to update notification: ${e.message}")
        }
    }

    private fun startVpn() {
        val gen: Int
        synchronized(vpnLock) {
            if (isRunning || isStarting) return
            isStarting = true
            lastError = null
            gen = vpnGeneration.incrementAndGet()
        }

        try {
            val builder = Builder()
                .setSession("wing")
                .setMtu(1400)
                .addAddress("172.19.0.1", 30)
                .addAddress("fdfe:dcba:9876::1", 126)
                .addDnsServer("172.19.0.2")
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .setBlocking(false)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            // Exclude the wing app itself so its outbound connections don't loop into the TUN interface
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to exclude own package from VPN: ${e.message}", e)
                failVpn("无法将应用自身排除出 VPN 隧道")
                return
            }

            val established = builder.establish()
            if (established == null) {
                failVpn("系统未能建立 VPN 接口")
                return
            }

            synchronized(vpnLock) {
                if (gen != vpnGeneration.get()) {
                    try {
                        established.close()
                    } catch (_: Exception) {
                    }
                    return
                }
                try {
                    vpnInterface?.close()
                } catch (_: Exception) {
                }
                vpnInterface = established
            }

            registerUnderlyingNetworkCallback()
            Log.i(TAG, "VPN interface established (gen=$gen). Ensuring Go backend is ready...")

            thread(name = "wing-vpn-attach-$gen", isDaemon = true) {
                val launch = WingBackendManager.ensureBackendRunning(applicationContext)
                if (gen != vpnGeneration.get()) return@thread
                if (!launch.ready) {
                    failVpn(launch.error ?: "内置代理核心启动失败")
                    return@thread
                }

                val fd = synchronized(vpnLock) {
                    if (gen == vpnGeneration.get()) vpnInterface?.fileDescriptor else null
                } ?: return@thread

                if (sendFdToGoBackend(fd, gen, failServiceOnError = true)) {
                    startBackendWatchdog(gen)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error starting VPN: ${e.message}", e)
            failVpn("VPN 启动失败：${e.message ?: e.javaClass.simpleName}")
        }
    }

    private fun reconnectBackend() {
        val gen: Int
        val currentInterface: ParcelFileDescriptor
        synchronized(vpnLock) {
            currentInterface = vpnInterface ?: return
            if (isStarting) return
            isRunning = false
            isStarting = true
            lastError = null
            gen = vpnGeneration.get()
        }

        notifyState(false)
        thread(name = "wing-vpn-reconnect-$gen", isDaemon = true) {
            try {
                val launch = WingBackendManager.ensureBackendRunning(applicationContext)
                if (gen != vpnGeneration.get()) return@thread
                if (!launch.ready) {
                    synchronized(vpnLock) {
                        if (gen == vpnGeneration.get()) {
                            isStarting = false
                            isRunning = false
                            lastError = launch.error ?: "内置代理核心重连失败"
                        }
                    }
                    startBackendWatchdog(gen)
                    return@thread
                }

                val fd = synchronized(vpnLock) {
                    if (gen == vpnGeneration.get()) currentInterface.fileDescriptor else null
                } ?: return@thread

                sendFdToGoBackend(fd, gen, failServiceOnError = false)
                startBackendWatchdog(gen)
            } catch (e: Exception) {
                Log.e(TAG, "Error reconnecting backend: ${e.message}", e)
                synchronized(vpnLock) {
                    if (gen == vpnGeneration.get()) {
                        isStarting = false
                        isRunning = false
                    }
                }
            }
        }
    }

    private fun sendFdToGoBackend(
        fd: FileDescriptor,
        gen: Int,
        failServiceOnError: Boolean
    ): Boolean {
        var retries = 0
        while (gen == vpnGeneration.get() && retries < 30) {
            var socket: LocalSocket? = null
            var commandSent = false
            try {
                socket = LocalSocket()
                socket.connect(LocalSocketAddress(ABSTRACT_SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT))
                socket.setFileDescriptorsForSend(arrayOf(fd))
                socket.soTimeout = 15000
                val output = socket.outputStream
                output.write(CMD_START) // start command; also triggers SCM_RIGHTS transmission
                output.flush()
                commandSent = true
                val input = socket.inputStream
                val acknowledged = input.read() == 1
                val detail = input.bufferedReader(Charsets.UTF_8).readText().trim()
                if (gen != vpnGeneration.get()) {
                    return false
                }
                if (acknowledged) {
                    synchronized(vpnLock) {
                        if (gen != vpnGeneration.get()) return false
                        isRunning = true
                        isStarting = false
                    }
                    notifyState(true)
                    Log.i(TAG, "VPN FD accepted by Go backend via @$ABSTRACT_SOCKET_NAME (gen=$gen)")
                    return true
                }
                val msg = if (detail.isNotEmpty()) {
                    "内置代理核心未能接管 VPN 隧道：$detail"
                } else {
                    "内置代理核心未能接管 VPN 隧道"
                }
                if (failServiceOnError) {
                    failVpn(msg)
                } else {
                    synchronized(vpnLock) {
                        if (gen == vpnGeneration.get()) {
                            lastError = msg
                            isStarting = false
                            isRunning = false
                        }
                    }
                }
                return false
            } catch (e: Exception) {
                if (gen != vpnGeneration.get()) {
                    return false
                }
                if (commandSent) {
                    if (failServiceOnError) {
                        failVpn("内置代理核心接管 VPN 隧道超时")
                    } else {
                        synchronized(vpnLock) {
                            if (gen == vpnGeneration.get()) {
                                lastError = "内置代理核心接管 VPN 隧道超时"
                                isStarting = false
                                isRunning = false
                            }
                        }
                    }
                    return false
                }
                retries++
                if (retries < 30) {
                    try {
                        Thread.sleep(500)
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                        return false
                    }
                }
            } finally {
                try {
                    socket?.close()
                } catch (_: Exception) {
                }
            }
        }
        if (gen == vpnGeneration.get()) {
            Log.w(TAG, "Could not send FD to Go backend after 30 retries")
            if (failServiceOnError) {
                failVpn("无法连接内置代理核心，请重新启动应用")
            } else {
                synchronized(vpnLock) {
                    if (gen == vpnGeneration.get()) {
                        lastError = "无法连接内置代理核心"
                        isStarting = false
                        isRunning = false
                    }
                }
            }
        }
        return false
    }

    private fun startBackendWatchdog(gen: Int) {
        synchronized(vpnLock) {
            if (gen != vpnGeneration.get() || watchdogGeneration == gen) return
            watchdogGeneration = gen
        }

        thread(name = "wing-vpn-watchdog-$gen", isDaemon = true) {
            while (gen == vpnGeneration.get() && WingBackendManager.isVpnDesired(applicationContext)) {
                try {
                    Thread.sleep(5000)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return@thread
                }
                if (gen != vpnGeneration.get() || !WingBackendManager.isVpnDesired(applicationContext)) {
                    return@thread
                }
                if (isStarting) continue

                if (WingBackendManager.isBackendHealthy(1500)) {
                    continue
                }

                // Require 3 consecutive health check failures before restarting core.
                var unhealthyCount = 1
                while (unhealthyCount < 3 && gen == vpnGeneration.get() && WingBackendManager.isVpnDesired(applicationContext)) {
                    try {
                        Thread.sleep(1000)
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                        return@thread
                    }
                    if (WingBackendManager.isBackendHealthy(1500)) {
                        unhealthyCount = 0
                        break
                    }
                    unhealthyCount++
                }
                if (unhealthyCount < 3 || gen != vpnGeneration.get() || !WingBackendManager.isVpnDesired(applicationContext)) {
                    continue
                }

                Log.w(TAG, "Go backend health checks failed; attempting recovery without closing VPN interface...")
                synchronized(vpnLock) {
                    if (gen != vpnGeneration.get()) return@thread
                    isRunning = false
                    isStarting = true
                }
                notifyState(false)

                val launch = WingBackendManager.ensureBackendRunning(applicationContext)
                if (gen != vpnGeneration.get()) return@thread
                if (!launch.ready) {
                    synchronized(vpnLock) {
                        if (gen == vpnGeneration.get()) {
                            isStarting = false
                        }
                    }
                    Log.e(TAG, "Backend recovery failed: ${launch.error}")
                    continue
                }

                val fd = synchronized(vpnLock) {
                    if (gen == vpnGeneration.get()) vpnInterface?.fileDescriptor else null
                } ?: return@thread

                sendFdToGoBackend(fd, gen, failServiceOnError = false)
            }
        }
    }

    private fun registerUnderlyingNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        synchronized(vpnLock) {
            if (networkCallback != null) return
            availableNetworks.clear()
        }

        val requestBuilder = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            requestBuilder.addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }
        val request = requestBuilder.build()

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val id = network.toString()
                synchronized(vpnLock) {
                    availableNetworks[id] = network
                }
                applyPreferredUnderlyingNetwork(cm)
            }

            override fun onLost(network: Network) {
                val id = network.toString()
                synchronized(vpnLock) {
                    availableNetworks.remove(id)
                }
                applyPreferredUnderlyingNetwork(cm)
            }
        }

        try {
            cm.registerNetworkCallback(request, callback)
            synchronized(vpnLock) {
                networkCallback = callback
            }
        } catch (e: Exception) {
            Log.w(TAG, "registerNetworkCallback failed: ${e.message}")
        }
    }

    private fun networkTransportPriority(cm: ConnectivityManager, network: Network): Int {
        val caps = try {
            cm.getNetworkCapabilities(network)
        } catch (_: Exception) {
            null
        } ?: return 0
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 3
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 2
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 1
            else -> 0
        }
    }

    private fun applyPreferredUnderlyingNetwork(cm: ConnectivityManager) {
        val snapshot = synchronized(vpnLock) {
            availableNetworks.values.toList()
        }
        var best: Network? = null
        var bestPriority = -1
        for (net in snapshot) {
            val priority = networkTransportPriority(cm, net)
            if (best == null || priority > bestPriority) {
                best = net
                bestPriority = priority
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            try {
                setUnderlyingNetworks(if (best != null) arrayOf(best) else null)
            } catch (e: Exception) {
                Log.w(TAG, "setUnderlyingNetworks failed: ${e.message}")
            }
        }

        val bestId = best?.toString()
        val changed: Boolean
        synchronized(vpnLock) {
            if (bestId != null) {
                changed = lastNotifiedNetworkId != null && lastNotifiedNetworkId != bestId
                lastNotifiedNetworkId = bestId
            } else {
                changed = false
            }
        }
        if (changed && (isRunning || isStarting)) {
            scheduleNetworkChangedNotification()
        }
    }

    private fun unregisterUnderlyingNetworkCallback() {
        val callback: ConnectivityManager.NetworkCallback?
        synchronized(vpnLock) {
            callback = networkCallback
            networkCallback = null
            availableNetworks.clear()
            lastNotifiedNetworkId = null
        }
        if (callback == null) return
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
            cm.unregisterNetworkCallback(callback)
        } catch (_: Exception) {
        }
    }

    private fun scheduleNetworkChangedNotification() {
        val seq = netChangeSequence.incrementAndGet()
        val gen = vpnGeneration.get()
        thread(name = "wing-net-change-$seq", isDaemon = true) {
            try {
                Thread.sleep(600)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return@thread
            }
            if (seq != netChangeSequence.get() || gen != vpnGeneration.get()) return@thread
            if (!isRunning) return@thread
            sendControlCommandToGoBackend(CMD_NETWORK_CHANGED)
        }
    }

    private fun failVpn(message: String) {
        lastError = message
        WingBackendManager.setVpnDesired(applicationContext, false)
        Log.e(TAG, message)
        stopVpn()
        stopSelf()
    }

    private fun stopVpn() {
        val wasActive: Boolean
        val toClose: ParcelFileDescriptor?
        synchronized(vpnLock) {
            vpnGeneration.incrementAndGet()
            netChangeSequence.incrementAndGet()
            watchdogGeneration = 0
            wasActive = isRunning || isStarting
            isStarting = false
            isRunning = false
            toClose = vpnInterface
            vpnInterface = null
        }

        unregisterUnderlyingNetworkCallback()

        if (wasActive) {
            sendControlCommandToGoBackend(CMD_STOP)
        }
        try {
            toClose?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface: ${e.message}")
        }
        leaveForeground()
        Log.i(TAG, "VPN stopped")
    }

    private fun sendControlCommandToGoBackend(cmd: Int) {
        var socket: LocalSocket? = null
        try {
            socket = LocalSocket()
            socket.connect(LocalSocketAddress(ABSTRACT_SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT))
            socket.soTimeout = 3000
            val output = socket.outputStream
            output.write(cmd)
            output.flush()
            try {
                socket.inputStream.read()
            } catch (_: Exception) {
            }
        } catch (e: Exception) {
            Log.w(TAG, "Could not send VPN control cmd=$cmd to Go backend: ${e.message}")
        } finally {
            try {
                socket?.close()
            } catch (_: Exception) {
            }
        }
    }

    override fun onRevoke() {
        WingBackendManager.setVpnDesired(applicationContext, false)
        stopVpn()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "wing VPN Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "wing VPN active connection notification"
                setShowBadge(false)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(connected: Boolean): Notification {
        val launchIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntentFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            launchIntent,
            pendingIntentFlags
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("wing 代理服务")
            .setContentText(
                if (connected) "VPN 已连接，正在保护您的网络连接" else "正在建立 VPN 安全隧道"
            )
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .build()
    }
}
