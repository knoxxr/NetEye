package com.neteye.sensor

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class SensorService : Service() {

    enum class Status { STOPPED, STARTING, READY, ERROR }

    data class State(
        val status: Status,
        val message: String = "",
        val url: String = "http://127.0.0.1:8000/"
    )

    companion object {
        private const val TAG = "NetEyeSensor"
        private const val CHANNEL_ID = "neteye_sensor_channel"
        private const val NOTIFICATION_ID = 1001
        const val ACTION_RESTART = "com.neteye.sensor.RESTART"
        const val PORT = 8000
        const val BASE_URL = "http://127.0.0.1:$PORT/"

        val state = AtomicReference(State(Status.STOPPED))
        private val listeners = CopyOnWriteArrayList<(State) -> Unit>()

        fun addListener(listener: (State) -> Unit) {
            listeners.add(listener)
            listener(state.get())
        }

        fun removeListener(listener: (State) -> Unit) {
            listeners.remove(listener)
        }

        private fun updateState(newState: State) {
            state.set(newState)
            for (listener in listeners) {
                listener(newState)
            }
        }
    }

    private val running = AtomicBoolean(false)
    @Volatile
    private var sensorProcess: Process? = null
    private var workerThread: Thread? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundNotification()
        if (intent?.action == ACTION_RESTART) {
            stopSensorProcess()
            running.set(false)
        }
        if (running.compareAndSet(false, true)) {
            workerThread = Thread({ runSensor() }, "neteye-sensor-launcher").apply {
                isDaemon = true
                start()
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running.set(false)
        stopSensorProcess()
        updateState(State(Status.STOPPED))
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            "NetEye Local Sensor",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "NetEye OT Security Monitor local sensor status"
        }
        manager.createNotificationChannel(channel)
    }

    private fun startForegroundNotification() {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("NetEye OT Security Monitor")
            .setContentText("Local sensor running (127.0.0.1:$PORT)")
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun runSensor() {
        try {
            updateState(State(Status.STARTING, "Preparing dashboard and offline databases..."))
            val frontendDir = File(filesDir, "frontend")
            val dataDir = File(filesDir, "data")
            dataDir.mkdirs()

            extractFrontendIfNeeded(frontendDir)
            extractDefaultData(dataDir)

            val nativeDir = File(applicationInfo.nativeLibraryDir)
            val neteyeBin = File(nativeDir, "libneteye.so")
            val bangdbBin = File(nativeDir, "libbangdb.so")
            if (!neteyeBin.exists() || !bangdbBin.exists()) {
                throw IllegalStateException("Bundled sensor binaries not found (${nativeDir.absolutePath})")
            }

            updateState(State(Status.STARTING, "Starting BangDB and NetEye engine..."))
            val pb = ProcessBuilder(neteyeBin.absolutePath, "serve").apply {
                directory(dataDir)
                redirectErrorStream(true)
                environment().apply {
                    put("NETEYE_HOST", "127.0.0.1")
                    put("NETEYE_PORT", PORT.toString())
                    put("NETEYE_BANGDB_BIN", bangdbBin.absolutePath)
                    put("NETEYE_FRONTEND", frontendDir.absolutePath)
                    put("NETEYE_DB", File(dataDir, "neteye.bdb").absolutePath)
                    put("NETEYE_VULNDB", File(dataDir, "vulndb.json").absolutePath)
                    put("NETEYE_IPASN", File(dataDir, "ip2asn-v4.tsv.gz").absolutePath)
                    put("NETEYE_BLOCKLIST", File(dataDir, "blocklist.txt").absolutePath)
                    put("TMPDIR", cacheDir.absolutePath)
                }
            }

            val proc = pb.start()
            sensorProcess = proc

            val recentLogs = ArrayDeque<String>(24)
            Thread({
                try {
                    BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                        var line = reader.readLine()
                        while (line != null) {
                            Log.i(TAG, line)
                            synchronized(recentLogs) {
                                if (recentLogs.size >= 20) recentLogs.removeFirst()
                                recentLogs.addLast(line)
                            }
                            line = reader.readLine()
                        }
                    }
                } catch (_: Exception) {
                }
            }, "neteye-log-reader").apply {
                isDaemon = true
                start()
            }

            val deadline = System.currentTimeMillis() + 30_000L
            while (running.get() && System.currentTimeMillis() < deadline) {
                if (!proc.isAlive) {
                    val tail = synchronized(recentLogs) { recentLogs.joinToString("\n") }
                    throw IllegalStateException("Sensor process exited unexpectedly (code=${proc.exitValue()})\n$tail")
                }
                if (probeServer()) {
                    updateState(State(Status.READY, "Running", BASE_URL))
                    return
                }
                Thread.sleep(250)
            }
            if (running.get()) {
                val tail = synchronized(recentLogs) { recentLogs.joinToString("\n") }
                throw IllegalStateException("Timed out waiting for local sensor\n$tail")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start NetEye sensor", e)
            running.set(false)
            stopSensorProcess()
            updateState(State(Status.ERROR, e.message ?: "Unknown error"))
        }
    }

    private fun probeServer(): Boolean {
        return try {
            val conn = (URL("${BASE_URL}login.html").openConnection() as HttpURLConnection).apply {
                connectTimeout = 500
                readTimeout = 500
                requestMethod = "GET"
            }
            try {
                conn.responseCode in 200..399
            } finally {
                conn.disconnect()
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun extractFrontendIfNeeded(dest: File) {
        val appVer = packageManager.getPackageInfo(packageName, 0).versionName ?: "0"
        val stamp = File(dest, ".version")
        if (stamp.exists() && stamp.readText().trim() == appVer) {
            return
        }
        dest.deleteRecursively()
        dest.mkdirs()
        copyAssetTree("frontend", dest)
        stamp.writeText(appVer)
    }

    private fun extractDefaultData(dataDir: File) {
        val entries = assets.list("data") ?: return
        for (name in entries) {
            val outName = name.removeSuffix(".bin")
            val target = File(dataDir, outName)
            if (!target.exists()) {
                val tmp = File(dataDir, ".$outName.tmp")
                assets.open("data/$name").use { input ->
                    tmp.outputStream().use { output -> input.copyTo(output) }
                }
                if (!tmp.renameTo(target)) {
                    tmp.copyTo(target, overwrite = true)
                    tmp.delete()
                }
            }
        }
    }

    private fun copyAssetTree(assetPath: String, destDir: File) {
        val list = assets.list(assetPath) ?: return
        if (list.isEmpty()) {
            destDir.parentFile?.mkdirs()
            assets.open(assetPath).use { input ->
                destDir.outputStream().use { output -> input.copyTo(output) }
            }
        } else {
            destDir.mkdirs()
            for (child in list) {
                copyAssetTree("$assetPath/$child", File(destDir, child))
            }
        }
    }

    private fun stopSensorProcess() {
        val proc = sensorProcess ?: return
        sensorProcess = null
        try {
            proc.destroy()
            if (!proc.waitFor(2, TimeUnit.SECONDS)) {
                proc.destroyForcibly()
            }
        } catch (_: Exception) {
            try {
                proc.destroyForcibly()
            } catch (_: Exception) {
            }
        }
    }
}
