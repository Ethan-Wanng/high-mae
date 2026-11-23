package com.highmae.wing_ui

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process as AndroidProcess
import android.provider.Settings
import android.util.Log
import java.io.File
import java.net.HttpURLConnection
import java.net.Inet6Address
import java.net.URL
import java.util.UUID
import kotlin.concurrent.thread

object WingBackendManager {
    private const val TAG = "WingBackendManager"
    private const val PREFS = "wing_native"
    private const val TOKEN_KEY = "mobile_api_token"
    private const val VPN_DESIRED_KEY = "vpn_desired_running"
    private const val VPN_DESIRED_BOOT_COUNT_KEY = "vpn_desired_boot_count"
    private const val PID_FILE_NAME = "wing_backend.pid"
    private const val ANDROID_CERT_DIRS =
        "/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts:/data/misc/keychain/certs-added"

    @Volatile
    private var backendProcess: Process? = null

    private val backendLock = Any()

    data class LaunchResult(
        val ready: Boolean,
        val token: String,
        val restarted: Boolean,
        val error: String?,
        val abi: String
    )

    fun getOrCreateMobileApiToken(context: Context): String {
        val appContext = context.applicationContext
        val preferences = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val existing = preferences.getString(TOKEN_KEY, null)
        if (!existing.isNullOrBlank()) return existing
        val created = UUID.randomUUID().toString() + UUID.randomUUID().toString()
        preferences.edit().putString(TOKEN_KEY, created).apply()
        return created
    }

    private fun currentBootCount(context: Context): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return -1
        }
        return try {
            Settings.Global.getInt(
                context.applicationContext.contentResolver,
                Settings.Global.BOOT_COUNT,
                -1
            )
        } catch (_: Exception) {
            -1
        }
    }

    fun isVpnDesired(context: Context): Boolean {
        val preferences = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return preferences.getBoolean(VPN_DESIRED_KEY, false)
    }

    fun isVpnDesiredForCurrentBoot(context: Context): Boolean {
        val appContext = context.applicationContext
        val preferences = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!preferences.getBoolean(VPN_DESIRED_KEY, false)) {
            return false
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val savedBootCount = preferences.getInt(VPN_DESIRED_BOOT_COUNT_KEY, -1)
            val bootCount = currentBootCount(appContext)
            if (savedBootCount >= 0 && bootCount >= 0 && savedBootCount != bootCount) {
                setVpnDesired(appContext, false)
                return false
            }
        }
        return true
    }

    fun setVpnDesired(context: Context, desired: Boolean) {
        val appContext = context.applicationContext
        val preferences = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val editor = preferences.edit().putBoolean(VPN_DESIRED_KEY, desired)
        if (desired) {
            val bootCount = currentBootCount(appContext)
            if (bootCount >= 0) {
                editor.putInt(VPN_DESIRED_BOOT_COUNT_KEY, bootCount)
            } else {
                editor.remove(VPN_DESIRED_BOOT_COUNT_KEY)
            }
        } else {
            editor.remove(VPN_DESIRED_BOOT_COUNT_KEY)
        }
        editor.apply()
    }

    fun isProcessAlive(process: Process?): Boolean {
        if (process == null) return false
        return try {
            process.exitValue()
            false
        } catch (_: IllegalThreadStateException) {
            true
        }
    }

    fun isBackendHealthy(timeoutMs: Int = 1000): Boolean {
        var connection: HttpURLConnection? = null
        return try {
            connection = URL("http://127.0.0.1:10809/healthz").openConnection() as HttpURLConnection
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs
            connection.requestMethod = "GET"
            connection.responseCode in 200..299
        } catch (_: Exception) {
            false
        } finally {
            try {
                connection?.inputStream?.close()
            } catch (_: Exception) {
            }
            connection?.disconnect()
        }
    }

    fun isBackendResponsive(attempts: Int = 3, timeoutMs: Int = 1000): Boolean {
        for (i in 0 until attempts) {
            if (isBackendHealthy(timeoutMs)) return true
            if (i + 1 < attempts) {
                try {
                    Thread.sleep(300)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return false
                }
            }
        }
        return false
    }

    fun ensureBackendRunning(context: Context): LaunchResult {
        val appContext = context.applicationContext
        val token = getOrCreateMobileApiToken(appContext)
        val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"
        var error: String? = null
        var restarted = false

        try {
            synchronized(backendLock) {
                if (isBackendHealthy(1000)) {
                    return LaunchResult(ready = true, token = token, restarted = false, error = null, abi = abi)
                }
                if (isProcessAlive(backendProcess) && isBackendResponsive(attempts = 3, timeoutMs = 1000)) {
                    return LaunchResult(ready = true, token = token, restarted = false, error = null, abi = abi)
                }

                terminateProcess(backendProcess)
                backendProcess = null
                killOrphanedBackend(appContext.filesDir)

                val backend = File(appContext.applicationInfo.nativeLibraryDir, "libwing_backend.so")
                if (!backend.exists()) {
                    error = "当前 APK 不包含 $abi 的代理核心"
                } else {
                    if (!backend.canExecute()) {
                        backend.setExecutable(true, true)
                    }
                    val systemDns = collectSystemDnsServers(appContext)
                    val process = ProcessBuilder(backend.absolutePath)
                        .directory(appContext.filesDir)
                        .redirectErrorStream(true)
                        .apply {
                            environment()["WING_DB_PATH"] = File(appContext.filesDir, "wing.db").absolutePath
                            environment()["WING_MOBILE_API_TOKEN"] = token
                            environment()["GOMEMLIMIT"] = "64MiB"
                            environment()["GOGC"] = "20"
                            environment()["SSL_CERT_DIR"] = ANDROID_CERT_DIRS
                            if (systemDns.isNotEmpty()) {
                                environment()["WING_ANDROID_DNS_SERVERS"] = systemDns.joinToString(",")
                            }
                        }
                        .start()
                    restarted = true
                    backendProcess = process

                    thread(name = "wing-backend-log", isDaemon = true) {
                        try {
                            process.inputStream.bufferedReader().useLines { lines ->
                                lines.forEach { Log.i(TAG, "backend: $it") }
                            }
                        } catch (_: Exception) {
                        }
                    }

                    for (attempt in 0 until 80) {
                        if (isBackendHealthy(500)) break
                        if (!isProcessAlive(process)) {
                            error = "代理核心已退出（exit ${process.exitValue()}）"
                            break
                        }
                        Thread.sleep(100)
                    }
                    if (error == null && !isBackendHealthy(500)) {
                        error = "代理核心启动超时"
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start backend", e)
            error = e.message ?: e.javaClass.simpleName
        }

        val ready = error == null && isBackendHealthy(1000)
        return LaunchResult(
            ready = ready,
            token = token,
            restarted = restarted,
            error = error,
            abi = abi
        )
    }

    private fun collectSystemDnsServers(context: Context): List<String> {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return emptyList()

            val orderedNetworks = ArrayList<Network>()
            val seenNetworkIds = HashSet<String>()

            fun addIfUsable(network: Network?) {
                if (network == null) return
                val id = network.toString()
                if (seenNetworkIds.contains(id)) return
                val caps = try {
                    cm.getNetworkCapabilities(network)
                } catch (_: Exception) {
                    null
                } ?: return
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                ) {
                    return
                }
                seenNetworkIds.add(id)
                orderedNetworks.add(network)
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                addIfUsable(cm.activeNetwork)
            }

            @Suppress("DEPRECATION")
            val allNetworks = try {
                cm.allNetworks
            } catch (_: Exception) {
                emptyArray()
            }
            val extraNetworks = allNetworks.mapNotNull { net ->
                val caps = try {
                    cm.getNetworkCapabilities(net)
                } catch (_: Exception) {
                    null
                } ?: return@mapNotNull null
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                ) {
                    return@mapNotNull null
                }
                val priority = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 3
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 2
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 1
                    else -> 0
                }
                Pair(priority, net)
            }.sortedByDescending { it.first }

            for ((_, net) in extraNetworks) {
                addIfUsable(net)
            }

            val dnsServers = LinkedHashSet<String>()
            for (net in orderedNetworks) {
                val linkProps = try {
                    cm.getLinkProperties(net)
                } catch (_: Exception) {
                    null
                } ?: continue
                for (addr in linkProps.dnsServers) {
                    if (addr.isLoopbackAddress ||
                        addr.isAnyLocalAddress ||
                        addr.isLinkLocalAddress ||
                        addr.isMulticastAddress
                    ) {
                        continue
                    }
                    val rawHost = addr.hostAddress ?: continue
                    val host = rawHost.substringBefore('%').trim()
                    if (host.isEmpty() || host == "172.19.0.2") {
                        continue
                    }
                    val formatted = if (addr is Inet6Address) "[$host]:53" else "$host:53"
                    dnsServers.add(formatted)
                }
            }
            dnsServers.toList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun terminateProcess(process: Process?) {
        if (process == null) return
        try {
            if (isProcessAlive(process)) {
                process.destroy()
                val deadline = System.currentTimeMillis() + 500L
                while (isProcessAlive(process) && System.currentTimeMillis() < deadline) {
                    Thread.sleep(50)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && isProcessAlive(process)) {
                    process.destroyForcibly()
                }
            }
        } catch (_: Exception) {
        }
    }

    private fun killOrphanedBackend(filesDir: File) {
        val pidFile = File(filesDir, PID_FILE_NAME)
        if (!pidFile.exists()) return
        try {
            val pid = pidFile.readText().trim().toIntOrNull()
            if (pid != null && pid > 0 && pid != AndroidProcess.myPid()) {
                val cmdlineFile = File("/proc/$pid/cmdline")
                if (cmdlineFile.exists()) {
                    val cmdline = String(cmdlineFile.readBytes(), Charsets.UTF_8).replace('\u0000', ' ')
                    if (cmdline.contains("libwing_backend.so")) {
                        AndroidProcess.killProcess(pid)
                        Thread.sleep(150)
                    }
                }
            }
        } catch (_: Exception) {
        } finally {
            try {
                pidFile.delete()
            } catch (_: Exception) {
            }
        }
    }
}
