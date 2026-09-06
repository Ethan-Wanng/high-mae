package com.highmae.wing_ui

import android.app.Activity
import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.util.Log
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import kotlin.concurrent.thread
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    companion object {
        private const val TAG = "WingMainActivity"
        private const val PREFS = "wing_native"
        private const val TOKEN_KEY = "mobile_api_token"

        @Volatile
        private var backendProcess: Process? = null

        private val backendLock = Any()
    }

    private val CHANNEL = "com.highmae.wing/vpn"
    private val VPN_REQUEST_CODE = 10809
    private val NOTIFICATION_REQUEST_CODE = 10810
    private var pendingVpnResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "startVpn" -> {
                    val intent = VpnService.prepare(this)
                    if (intent != null) {
                        pendingVpnResult = result
                        startActivityForResult(intent, VPN_REQUEST_CODE)
                    } else {
                        startVpnAndWait(result)
                    }
                }
                "stopVpn" -> {
                    stopVpnService()
                    result.success(true)
                }
                "getVpnStatus" -> {
                    result.success(WingVpnService.isRunning)
                }
                "startBackend" -> {
                    startBackend(result)
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

    private fun stopVpnService() {
        stopService(Intent(this, WingVpnService::class.java))
    }

    private fun reconnectVpnBackend() {
        if (!WingVpnService.isRunning) return
        val intent = Intent(this, WingVpnService::class.java).apply {
            action = WingVpnService.ACTION_RECONNECT
        }
        startService(intent)
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
        val token = getOrCreateMobileApiToken()
        thread(name = "wing-backend-launch", isDaemon = true) {
            var error: String? = null
            var restarted = false
            try {
                synchronized(backendLock) {
                    if (!isBackendReady(token)) {
                        backendProcess?.let { existing ->
                            if (existing.isAlive) {
                                existing.destroy()
                                Thread.sleep(250)
                                if (existing.isAlive) existing.destroyForcibly()
                            }
                        }
                        val backend = File(applicationInfo.nativeLibraryDir, "libwing_backend.so")
                        if (!backend.exists()) {
                            error = "当前 APK 不包含 ${Build.SUPPORTED_ABIS.firstOrNull() ?: "此设备"} 的代理核心"
                        } else {
                            backend.setExecutable(true, true)
                            val process = ProcessBuilder(backend.absolutePath)
                                .directory(filesDir)
                                .redirectErrorStream(true)
                                .apply {
                                    environment()["WING_DB_PATH"] = File(filesDir, "wing.db").absolutePath
                                    environment()["WING_MOBILE_API_TOKEN"] = token
                                }
                                .start()
                            restarted = true
                            backendProcess = process
                            thread(name = "wing-backend-log", isDaemon = true) {
                                process.inputStream.bufferedReader().useLines { lines ->
                                    lines.forEach { Log.i(TAG, "backend: $it") }
                                }
                            }

                            for (attempt in 0 until 80) {
                                if (isBackendReady(token)) break
                                if (!process.isAlive) {
                                    error = "代理核心已退出（exit ${process.exitValue()}）"
                                    break
                                }
                                Thread.sleep(100)
                            }
                            if (!isBackendReady(token) && error == null) {
                                error = "代理核心启动超时"
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start backend", e)
                error = e.message ?: e.javaClass.simpleName
            }

            val payload = mapOf(
                "ready" to (error == null && isBackendReady(token)),
                "token" to token,
                "error" to error,
                "abi" to (Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown")
            )
            if (error == null && restarted) reconnectVpnBackend()
            runOnUiThread { result.success(payload) }
        }
    }

    private fun getOrCreateMobileApiToken(): String {
        val preferences = getSharedPreferences(PREFS, MODE_PRIVATE)
        val existing = preferences.getString(TOKEN_KEY, null)
        if (!existing.isNullOrBlank()) return existing
        val created = UUID.randomUUID().toString() + UUID.randomUUID().toString()
        preferences.edit().putString(TOKEN_KEY, created).apply()
        return created
    }

    private fun isBackendReady(token: String): Boolean {
        var connection: HttpURLConnection? = null
        return try {
            connection = URL("http://127.0.0.1:10809/api/status").openConnection() as HttpURLConnection
            connection.connectTimeout = 250
            connection.readTimeout = 250
            connection.requestMethod = "GET"
            connection.setRequestProperty("X-Wing-Mobile-Token", token)
            connection.responseCode in 200..299
        } catch (_: Exception) {
            false
        } finally {
            connection?.disconnect()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == Activity.RESULT_OK) {
                pendingVpnResult?.let { startVpnAndWait(it) }
            } else {
                pendingVpnResult?.success(false)
            }
            pendingVpnResult = null
        }
    }
}
