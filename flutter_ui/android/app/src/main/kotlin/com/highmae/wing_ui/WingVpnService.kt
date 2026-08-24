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
        const val CHANNEL_ID = "wing_vpn_channel"
        const val NOTIFICATION_ID = 10809
        const val ABSTRACT_SOCKET_NAME = "wing_vpn_fd"

        var isRunning = false
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        when (action) {
            ACTION_START -> {
                startVpn()
            }
            ACTION_STOP -> {
                stopVpn()
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun startVpn() {
        if (isRunning) return
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())

        try {
            val builder = Builder()
                .setSession("wing")
                .setMtu(1500)
                .addAddress("172.19.0.1", 30)
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
                Log.e(TAG, "Failed to establish VPN interface (null)")
                stopSelf()
                return
            }

            val fd = vpnInterface!!.fileDescriptor
            isRunning = true
            Log.i(TAG, "VPN interface established. Sending FD to Go backend...")

            // Send FD to Go backend in background thread
            thread {
                sendFdToGoBackend(fd)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error starting VPN: ${e.message}", e)
            stopSelf()
        }
    }

    private fun sendFdToGoBackend(fd: FileDescriptor) {
        var retries = 0
        while (isRunning && retries < 30) {
            try {
                val socket = LocalSocket()
                socket.connect(LocalSocketAddress(ABSTRACT_SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT))
                socket.setFileDescriptorsForSend(arrayOf(fd))
                val output = socket.outputStream
                output.write(1) // send 1 byte to trigger SCM_RIGHTS transmission
                output.flush()
                socket.close()
                Log.i(TAG, "Successfully passed VPN FD to Go backend via @$ABSTRACT_SOCKET_NAME")
                return
            } catch (e: Exception) {
                retries++
                Thread.sleep(500)
            }
        }
        Log.w(TAG, "Could not send FD to Go backend after 30 retries")
    }

    private fun stopVpn() {
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

    private fun createNotification(): Notification {
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
            .setContentText("正在通过安全隧道保护您的网络连接")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
}
