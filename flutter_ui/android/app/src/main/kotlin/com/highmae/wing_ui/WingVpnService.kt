package com.highmae.wing_ui

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileDescriptor
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

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        when (action) {
            ACTION_START -> startVpn()
            ACTION_STOP -> {
                stopVpn()
                stopSelf()
            }
            ACTION_RECONNECT -> reconnectBackend()
        }
        return START_NOT_STICKY
    }

    private fun startVpn() {
        if (isRunning || isStarting) return
        isStarting = true
        lastError = null
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification(false))

        try {
            val builder = Builder()
                .setSession("wing")
                .setMtu(1500)
                .addAddress("172.19.0.1", 30)
                .addAddress("fdfe:dcba:9876::1", 126)
                .addDnsServer("172.19.0.2")
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .setBlocking(false)

            // Exclude the wing app itself so its outbound connections don't loop into the TUN interface
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to exclude own package from VPN: ${e.message}")
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                failVpn("系统未能建立 VPN 接口")
                return
            }

            val fd = vpnInterface!!.fileDescriptor
            Log.i(TAG, "VPN interface established. Sending FD to Go backend...")

            // Send FD to Go backend in background thread
            thread {
                sendFdToGoBackend(fd)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error starting VPN: ${e.message}", e)
            failVpn("VPN 启动失败：${e.message ?: e.javaClass.simpleName}")
        }
    }

    private fun reconnectBackend() {
        val currentInterface = vpnInterface ?: return
        if (isStarting) return
        isRunning = false
        isStarting = true
        lastError = null
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, createNotification(false))
        thread {
            sendFdToGoBackend(currentInterface.fileDescriptor)
        }
    }

    private fun sendFdToGoBackend(fd: FileDescriptor) {
        var retries = 0
        while (isStarting && retries < 30) {
            var socket: LocalSocket? = null
            var commandSent = false
            try {
                socket = LocalSocket()
                socket.connect(LocalSocketAddress(ABSTRACT_SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT))
                socket.setFileDescriptorsForSend(arrayOf(fd))
                socket.soTimeout = 15000
                val output = socket.outputStream
                output.write(1) // start command; also triggers SCM_RIGHTS transmission
                output.flush()
                commandSent = true
                val input = socket.inputStream
                val acknowledged = input.read() == 1
                val detail = input.bufferedReader(Charsets.UTF_8).readText().trim()
                if (acknowledged) {
                    isRunning = true
                    isStarting = false
                    val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                    manager.notify(NOTIFICATION_ID, createNotification(true))
                    Log.i(TAG, "VPN FD accepted by Go backend via @$ABSTRACT_SOCKET_NAME")
                    return
                }
                failVpn(
                    if (detail.isNotEmpty()) "内置代理核心未能接管 VPN 隧道：$detail"
                    else "内置代理核心未能接管 VPN 隧道"
                )
                return
            } catch (e: Exception) {
                if (commandSent) {
                    failVpn("内置代理核心接管 VPN 隧道超时")
                    return
                }
                retries++
                if (retries < 30) Thread.sleep(500)
            } finally {
                try {
                    socket?.close()
                } catch (_: Exception) {
                }
            }
        }
        if (isStarting) {
            Log.w(TAG, "Could not send FD to Go backend after 30 retries")
            failVpn("无法连接内置代理核心，请重新启动应用")
        }
    }

    private fun failVpn(message: String) {
        lastError = message
        isStarting = false
        isRunning = false
        Log.e(TAG, message)
        stopVpn()
        stopSelf()
    }

    private fun stopVpn() {
        if (isRunning) {
            sendStopToGoBackend()
        }
        isStarting = false
        isRunning = false
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface: ${e.message}")
        }
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.i(TAG, "VPN stopped")
    }

    private fun sendStopToGoBackend() {
        try {
            val socket = LocalSocket()
            socket.connect(LocalSocketAddress(ABSTRACT_SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT))
            socket.outputStream.use { output ->
                output.write(0)
                output.flush()
            }
            socket.close()
        } catch (e: Exception) {
            Log.w(TAG, "Could not notify Go backend that VPN stopped: ${e.message}")
        }
    }

    override fun onRevoke() {
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
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            packageManager.getLaunchIntentForPackage(packageName),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
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
