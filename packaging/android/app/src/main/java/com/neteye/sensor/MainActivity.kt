package com.neteye.sensor

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import java.io.File

class MainActivity : Activity() {

    companion object {
        private const val REQ_FILE_CHOOSER = 2001
    }

    private lateinit var webView: WebView
    private lateinit var overlay: LinearLayout
    private lateinit var statusText: TextView
    private lateinit var spinner: ProgressBar
    private lateinit var retryButton: Button
    private lateinit var initPwBanner: LinearLayout
    private lateinit var initPwText: TextView

    private var filePathCallback: ValueCallback<Array<Uri>>? = null
    private var loadedUrl = false
    private var initialPassword: String? = null

    private val stateListener: (SensorService.State) -> Unit = { s ->
        runOnUiThread { renderState(s) }
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0b1220"))
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        // Initial admin password helper bar (auto-hidden once password is changed).
        initPwBanner = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(Color.parseColor("#132238"))
            val pad = dp(10)
            setPadding(pad, dp(6), pad, dp(6))
            visibility = View.GONE
        }
        initPwText = TextView(this).apply {
            setTextColor(Color.parseColor("#e2e8f0"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val copyBtn = Button(this).apply {
            text = "Copy Password"
            setTextColor(Color.parseColor("#0b1220"))
            setBackgroundColor(Color.parseColor("#2dd4bf"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(dp(10), dp(4), dp(10), dp(4))
            setOnClickListener {
                initialPassword?.let { pw ->
                    val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText("NetEye Admin Password", pw))
                    Toast.makeText(this@MainActivity, "Initial password copied", Toast.LENGTH_SHORT).show()
                }
            }
        }
        initPwBanner.addView(initPwText)
        initPwBanner.addView(copyBtn)
        root.addView(initPwBanner)

        val contentFrame = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
        }

        webView = WebView(this).apply {
            setBackgroundColor(Color.parseColor("#0b1220"))
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            settings.useWideViewPort = true
            settings.loadWithOverviewMode = true
            settings.builtInZoomControls = true
            settings.displayZoomControls = false

            webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    refreshInitialPasswordBanner()
                }
            }

            webChromeClient = object : WebChromeClient() {
                override fun onShowFileChooser(
                    webView: WebView?,
                    filePathCallback: ValueCallback<Array<Uri>>?,
                    fileChooserParams: FileChooserParams?
                ): Boolean {
                    this@MainActivity.filePathCallback?.onReceiveValue(null)
                    this@MainActivity.filePathCallback = filePathCallback
                    val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = "*/*"
                    }
                    return try {
                        @Suppress("DEPRECATION")
                        startActivityForResult(Intent.createChooser(intent, "Select PCAP or VulnDB file"), REQ_FILE_CHOOSER)
                        true
                    } catch (_: Exception) {
                        this@MainActivity.filePathCallback = null
                        false
                    }
                }
            }
        }
        contentFrame.addView(
            webView,
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        )

        overlay = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(Color.parseColor("#0b1220"))
            val p = dp(24)
            setPadding(p, p, p, p)
        }
        val title = TextView(this).apply {
            text = "NetEye OT Security Monitor"
            setTextColor(Color.parseColor("#2dd4bf"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 20f)
            gravity = Gravity.CENTER
        }
        spinner = ProgressBar(this).apply {
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dp(16)
            layoutParams = lp
        }
        statusText = TextView(this).apply {
            text = "Starting local sensor..."
            setTextColor(Color.parseColor("#cbd5e1"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            gravity = Gravity.CENTER
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dp(12)
            layoutParams = lp
        }
        retryButton = Button(this).apply {
            text = "Restart Sensor"
            visibility = View.GONE
            val lp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            lp.topMargin = dp(16)
            layoutParams = lp
            setOnClickListener {
                loadedUrl = false
                startForegroundService(Intent(this@MainActivity, SensorService::class.java).apply {
                    action = SensorService.ACTION_RESTART
                })
            }
        }
        overlay.addView(title)
        overlay.addView(spinner)
        overlay.addView(statusText)
        overlay.addView(retryButton)
        contentFrame.addView(
            overlay,
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        )

        root.addView(contentFrame)
        setContentView(root)

        startForegroundService(Intent(this, SensorService::class.java))
    }

    override fun onStart() {
        super.onStart()
        SensorService.addListener(stateListener)
    }

    override fun onStop() {
        SensorService.removeListener(stateListener)
        super.onStop()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack()
        } else {
            @Suppress("DEPRECATION")
            super.onBackPressed()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQ_FILE_CHOOSER) {
            val result = if (resultCode == RESULT_OK && data?.data != null) {
                arrayOf(data.data!!)
            } else {
                null
            }
            filePathCallback?.onReceiveValue(result)
            filePathCallback = null
            return
        }
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
    }

    private fun renderState(s: SensorService.State) {
        when (s.status) {
            SensorService.Status.READY -> {
                overlay.visibility = View.GONE
                refreshInitialPasswordBanner()
                if (!loadedUrl) {
                    loadedUrl = true
                    webView.loadUrl(s.url)
                }
            }
            SensorService.Status.ERROR -> {
                overlay.visibility = View.VISIBLE
                spinner.visibility = View.GONE
                retryButton.visibility = View.VISIBLE
                statusText.text = "Sensor startup failed:\n${s.message}"
            }
            SensorService.Status.STARTING, SensorService.Status.STOPPED -> {
                overlay.visibility = View.VISIBLE
                spinner.visibility = View.VISIBLE
                retryButton.visibility = View.GONE
                statusText.text = s.message.ifEmpty { "Starting local sensor..." }
            }
        }
    }

    private fun refreshInitialPasswordBanner() {
        val pwFile = File(File(filesDir, "data"), "initial-admin-password.txt")
        if (!pwFile.isFile) {
            initialPassword = null
            initPwBanner.visibility = View.GONE
            return
        }
        val pw = pwFile.readLines()
            .firstOrNull { it.startsWith("password:") }
            ?.substringAfter("password:")
            ?.trim()
        if (!pw.isNullOrEmpty()) {
            initialPassword = pw
            initPwText.text = "Initial Sign-In  admin / $pw"
            initPwBanner.visibility = View.VISIBLE
        } else {
            initPwBanner.visibility = View.GONE
        }
    }

    private fun dp(value: Int): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()
}
