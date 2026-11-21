package com.highmae.wing_ui

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    private class SafeMethodResult(private val delegate: MethodChannel.Result) : MethodChannel.Result {
        private val replied = AtomicBoolean(false)

        override fun success(result: Any?) {
            if (replied.compareAndSet(false, true)) {
                delegate.success(result)
            }
        }

        override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) {
            if (replied.compareAndSet(false, true)) {
                delegate.error(errorCode, errorMessage, errorDetails)
            }
        }

        override fun notImplemented() {
            if (replied.compareAndSet(false, true)) {
                delegate.notImplemented()
            }
        }
    }

    private val CHANNEL = "com.highmae.wing/vpn"
    private val VPN_REQUEST_CODE = 10809
    private val NOTIFICATION_REQUEST_CODE = 10810
    private var pendingVpnResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, rawResult ->
            val result = SafeMethodResult(rawResult)
            when (call.method) {
                "startVpn" -> {
                    val intent = VpnService.prepare(this)
                    if (intent != null) {
                        pendingVpnResult?.success(false)
                        pendingVpnResult = result
                        startActivityForResult(intent, VPN_REQUEST_CODE)
                    } else {
                        startVpnAndWait(result)
                    }
                }
                "stopVpn" -> {
                    stopVpnAndWait(result)
                }
                "getVpnStatus" -> {
                    result.success(
                        WingVpnService.isRunning ||
                            (WingVpnService.hasActiveTunnel && WingVpnService.isStarting)
                    )
                }
                "startBackend" -> {
                    startBackend(result)
                }
                "isIgnoringBatteryOptimizations" -> {
                    val ignoring = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager
                        pm?.isIgnoringBatteryOptimizations(packageName) ?: true
                    } else {
                        true
                    }
                    result.success(ignoring)
                }
                "openBatteryOptimizationSettings" -> {
                    var opened = false
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        try {
                            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                            opened = true
                        } catch (_: Exception) {
                        }
                    }
                    if (!opened) {
                        try {
                            val appIntent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                data = Uri.fromParts("package", packageName, null)
                            }
                            startActivity(appIntent)
                            opened = true
                        } catch (_: Exception) {
                        }
                    }
                    result.success(opened)
                }
                "shareText" -> {
                    val text = call.argument<String>("text")?.trim().orEmpty()
                    if (text.isEmpty()) {
                        result.error("EMPTY_TEXT", "没有可分享的内容", null)
                    } else {
                        val shareIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, text)
                            putExtra(Intent.EXTRA_SUBJECT, call.argument<String>("title") ?: "wing 订阅")
                        }
                        startActivity(Intent.createChooser(shareIntent, "分享订阅"))
                        result.success(true)
                    }
                }
                "getBackendPath" -> {
                    result.success(File(applicationInfo.nativeLibraryDir, "libwing_backend.so").absolutePath)
                }
                "getDataDirectory" -> {
                    result.success(filesDir.absolutePath)
                }
                else -> {
                    result.notImplemented()
                }
            }
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, WingVpnService::class.java).apply {
            action = WingVpnService.ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopVpnAndWait(result: MethodChannel.Result) {
        WingBackendManager.setVpnDesired(applicationContext, false)
        if (!WingVpnService.isRunning && !WingVpnService.isStarting && !WingVpnService.hasActiveTunnel) {
            result.success(true)
            return
        }
        val intent = Intent(this, WingVpnService::class.java).apply {
            action = WingVpnService.ACTION_STOP
        }
        try {
            startService(intent)
        } catch (_: Exception) {
            stopService(Intent(this, WingVpnService::class.java))
        }
        thread(name = "wing-vpn-stop", isDaemon = true) {
            for (attempt in 0 until 50) {
                if (!WingVpnService.isRunning && !WingVpnService.isStarting && !WingVpnService.hasActiveTunnel) {
                    runOnUiThread { result.success(true) }
                    return@thread
                }
                Thread.sleep(100)
            }
            stopService(Intent(this, WingVpnService::class.java))
            runOnUiThread {
                if (!WingVpnService.isRunning && !WingVpnService.isStarting && !WingVpnService.hasActiveTunnel) {
                    result.success(true)
                } else {
                    result.error("VPN_STOP_TIMEOUT", "VPN 隧道断开超时，请重试", null)
                }
            }
        }
    }

    private fun reconnectVpnBackend(): Boolean {
        if (!WingVpnService.hasActiveTunnel &&
            !WingVpnService.isRunning &&
            !WingBackendManager.isVpnDesiredForCurrentBoot(applicationContext)
        ) {
            return false
        }
        val intent = Intent(this, WingVpnService::class.java).apply {
            action = WingVpnService.ACTION_RECONNECT
        }
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun startVpnAndWait(result: MethodChannel.Result) {
        WingVpnService.prepareForStart()
        requestNotificationPermissionIfNeeded()
        startVpnService()
        thread(name = "wing-vpn-start", isDaemon = true) {
            for (attempt in 0 until 180) {
                if (WingVpnService.isRunning) {
                    runOnUiThread { result.success(true) }
                    return@thread
                }
                val error = WingVpnService.lastError
                if (!error.isNullOrBlank()) {
                    runOnUiThread { result.error("VPN_START_FAILED", error, null) }
                    return@thread
                }
                Thread.sleep(100)
            }
            runOnUiThread {
                result.error("VPN_START_TIMEOUT", "VPN 隧道启动超时，请重新连接", null)
            }
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                NOTIFICATION_REQUEST_CODE
            )
        }
    }

    private fun startBackend(result: MethodChannel.Result) {
        thread(name = "wing-backend-launch", isDaemon = true) {
            val launch = WingBackendManager.ensureBackendRunning(applicationContext)
            val payload = mapOf(
                "ready" to launch.ready,
                "token" to launch.token,
                "error" to launch.error,
                "abi" to launch.abi
            )
            val needsReconnect = launch.ready &&
                (launch.restarted ||
                    (!WingVpnService.isRunning &&
                        !WingVpnService.isStarting &&
                        WingBackendManager.isVpnDesiredForCurrentBoot(applicationContext)))
            if (needsReconnect && reconnectVpnBackend()) {
                for (attempt in 0 until 25) {
                    if (WingVpnService.isRunning ||
                        !WingVpnService.lastError.isNullOrBlank() ||
                        (attempt >= 3 && !WingVpnService.isStarting && !WingVpnService.hasActiveTunnel)
                    ) {
                        break
                    }
                    Thread.sleep(100)
                }
            }
            runOnUiThread { result.success(payload) }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            val pending = pendingVpnResult
            pendingVpnResult = null
            if (pending != null) {
                if (resultCode == Activity.RESULT_OK) {
                    startVpnAndWait(pending)
                } else {
                    pending.success(false)
                }
            }
        }
    }

    override fun onDestroy() {
        pendingVpnResult?.success(false)
        pendingVpnResult = null
        super.onDestroy()
    }
}
