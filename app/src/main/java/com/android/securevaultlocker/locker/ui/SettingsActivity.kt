package com.android.securevaultlocker.locker.ui

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.view.View
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import com.android.securevaultlocker.R
import com.android.securevaultlocker.locker.service.AppMonitorService
import com.android.securevaultlocker.locker.service.SecureVaultUsbManager

/** Central SecureVault control center: security setup, HSM health, diagnostics and recovery. */
class SettingsActivity : AppCompatActivity(), SecureVaultUsbManager.Listener {

    private val usbManager by lazy { SecureVaultUsbManager.get(this) }

    private lateinit var tvHsmStatus: TextView
    private lateinit var tvHsmDetail: TextView
    private lateinit var tvMonitoring: TextView
    private lateinit var tvOverlay: TextView
    private lateinit var tvCapacity: TextView
    private lateinit var tvLastEvent: TextView
    private lateinit var tvLastError: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContentView(R.layout.activity_settings)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.rootLayout)) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        findViewById<ImageButton>(R.id.btnBack).setOnClickListener { finish() }

        tvHsmStatus = findViewById(R.id.tvHsmStatus)
        tvHsmDetail = findViewById(R.id.tvHsmDetail)
        tvMonitoring = findViewById(R.id.tvMonitoringStatusVisible)
        tvOverlay = findViewById(R.id.tvOverlayStatusVisible)
        tvCapacity = findViewById(R.id.tvSlotCapacity)
        tvLastEvent = findViewById(R.id.tvLastEvent)
        tvLastError = findViewById(R.id.tvLastError)

        findViewById<View>(R.id.rowHsmStatus).setOnClickListener { showHsmStatusDialog() }
        findViewById<View>(R.id.rowConnectionTest).setOnClickListener { runConnectionTest() }
        findViewById<View>(R.id.rowReconnect).setOnClickListener { usbManager.reconnectByUserRequest(); refreshUi() }
        findViewById<View>(R.id.rowDisconnect).setOnClickListener { usbManager.disconnect("Settings: user disconnect"); refreshUi() }
        findViewById<View>(R.id.rowMonitoring).setOnClickListener {
            startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
        }
        findViewById<View>(R.id.rowOverlay).setOnClickListener {
            if (!Settings.canDrawOverlays(this)) {
                startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, android.net.Uri.parse("package:$packageName")))
            } else {
                toast("Lock overlay permission is already enabled")
            }
        }
        findViewById<View>(R.id.rowVault).setOnClickListener {
            startActivity(Intent(this, ApplicationVaultActivity::class.java))
        }
        findViewById<View>(R.id.rowRefreshConfig).setOnClickListener {
            AppMonitorService.loadConfiguredLocks(this)
            refreshUi()
            toast("Application protection configuration refreshed")
        }
        findViewById<View>(R.id.rowRevokeSessions).setOnClickListener {
            AppMonitorService.revokeAllSessions()
            toast("Active unlock sessions revoked")
        }
        findViewById<View>(R.id.rowViewLog).setOnClickListener { showLogDialog() }
        findViewById<View>(R.id.rowExportLog).setOnClickListener { exportLog() }
        findViewById<View>(R.id.rowClearLog).setOnClickListener { confirmClearLog() }
        findViewById<View>(R.id.rowSystemCheck).setOnClickListener { showSystemCheck() }
        findViewById<View>(R.id.rowAbout).setOnClickListener { showAboutDialog() }

        usbManager.addListener(this)
        refreshUi()
    }

    override fun onResume() {
        super.onResume()
        AppMonitorService.loadConfiguredLocks(this)
        refreshUi()
    }

    override fun onDestroy() {
        usbManager.removeListener(this)
        super.onDestroy()
    }

    private fun refreshUi() {
        val snapshot = usbManager.snapshot()
        tvHsmStatus.text = when (snapshot.state) {
            SecureVaultUsbManager.UsbState.READY -> "Connected"
            SecureVaultUsbManager.UsbState.HANDSHAKING,
            SecureVaultUsbManager.UsbState.CONNECTING,
            SecureVaultUsbManager.UsbState.PERMISSION_REQUESTED -> "Working…"
            SecureVaultUsbManager.UsbState.DEVICE_DETECTED,
            SecureVaultUsbManager.UsbState.PERMISSION_REQUIRED -> "Detected"
            SecureVaultUsbManager.UsbState.PERMISSION_DENIED -> "Permission denied"
            SecureVaultUsbManager.UsbState.ERROR -> "Needs attention"
            else -> "Not connected"
        }
        val hsmColor = when (snapshot.state) {
            SecureVaultUsbManager.UsbState.READY -> R.color.sv_success
            SecureVaultUsbManager.UsbState.HANDSHAKING,
            SecureVaultUsbManager.UsbState.CONNECTING,
            SecureVaultUsbManager.UsbState.DEVICE_DETECTED,
            SecureVaultUsbManager.UsbState.PERMISSION_REQUIRED,
            SecureVaultUsbManager.UsbState.PERMISSION_REQUESTED -> R.color.sv_warning
            SecureVaultUsbManager.UsbState.ERROR,
            SecureVaultUsbManager.UsbState.PERMISSION_DENIED -> R.color.sv_error
            else -> R.color.sv_text_muted
        }
        tvHsmStatus.setTextColor(getColor(hsmColor))
        tvHsmDetail.text = when {
            snapshot.ready -> "Serial connection established and hardware time is synchronized."
            snapshot.connected -> "USB link is open; SecureVault is completing hardware initialization."
            else -> "Use Connect ESP32 from Home to start a user-authorized USB session."
        }

        val monitoring = isAccessibilityServiceEnabled(this)
        val overlay = Settings.canDrawOverlays(this)
        tvMonitoring.text = if (monitoring) "Enabled" else "Not enabled"
        tvMonitoring.setTextColor(getColor(if (monitoring) R.color.sv_success else R.color.sv_warning))
        tvOverlay.text = if (overlay) "Enabled" else "Not enabled"
        tvOverlay.setTextColor(getColor(if (overlay) R.color.sv_success else R.color.sv_warning))

        tvCapacity.text = "${AppMonitorService.assignedSlots(this).size} / ${snapshot.slotCapacity} assigned"
        tvLastEvent.text = snapshot.lastProtocolEvent.ifBlank { "No HSM response yet" }
        tvLastError.text = snapshot.lastError ?: "None"
        tvLastError.setTextColor(getColor(if (snapshot.lastError == null) R.color.sv_text_muted else R.color.sv_error))

        findViewById<TextView>(R.id.tvProtectedSummary).text =
            "${AppMonitorService.configuredSlots(this).size} protected • ${AppMonitorService.assignedSlots(this).size} hardware assignments"
    }

    private fun runConnectionTest() {
        AlertDialog.Builder(this)
            .setTitle("Run connection test?")
            .setMessage("SecureVault will reconnect the ESP32 and verify the USB serial link, hardware handshake and time synchronization. No TOTP secret or code is displayed or logged.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Run test") { _, _ ->
                usbManager.reconnectByUserRequest()
                toast("Connection test started")
            }
            .show()
    }

    private fun showHsmStatusDialog() {
        val s = usbManager.snapshot()
        val message = buildString {
            append("State: ${s.state}\n")
            append("Connected: ${if (s.connected) "Yes" else "No"}\n")
            append("Ready: ${if (s.ready) "Yes" else "No"}\n")
            append("Firmware: SV2 / ${s.firmwareVersion}\n")
            append("Transport: ${s.transport}\n")
            append("Security authority: ${s.security}\n")
            append("Hardware capacity: ${s.slotCapacity} slots\n")
            append("Selected slot: ${s.selectedSlot ?: "None"}\n")
            append("Last response: ${s.lastProtocolEvent}\n")
            append("Last error: ${s.lastError ?: "None"}")
        }
        AlertDialog.Builder(this)
            .setTitle("HSM status")
            .setMessage(message)
            .setPositiveButton("Close", null)
            .show()
    }

    private fun showLogDialog() {
        val content = usbManager.diagnosticLog()
        val view = TextView(this).apply {
            setPadding(28, 20, 28, 20)
            setTextColor(getColor(R.color.sv_text_primary))
            textSize = 11f
            typeface = android.graphics.Typeface.MONOSPACE
            text = if (content.length > 12000) "…(older entries omitted)…\n" + content.takeLast(12000) else content
        }
        val scroll = ScrollView(this).apply { addView(view) }
        AlertDialog.Builder(this)
            .setTitle("USB diagnostic log")
            .setView(scroll)
            .setPositiveButton("Close", null)
            .show()
    }

    private fun exportLog() {
        val intent = usbManager.exportDiagnosticIntent(this)
        if (intent == null) {
            toast("No diagnostic log is available yet")
            return
        }
        startActivity(Intent.createChooser(intent, "Export USB diagnostic log"))
    }

    private fun confirmClearLog() {
        AlertDialog.Builder(this)
            .setTitle("Clear diagnostic log?")
            .setMessage("This removes the locally stored USB troubleshooting history. It does not change HSM credentials or application slot assignments.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Clear") { _, _ ->
                usbManager.clearDiagnosticLog()
                refreshUi()
                toast("Diagnostic log cleared")
            }
            .show()
    }

    private fun showSystemCheck() {
        val monitoring = isAccessibilityServiceEnabled(this)
        val overlay = Settings.canDrawOverlays(this)
        val snapshot = usbManager.snapshot()
        val configured = AppMonitorService.configuredSlots(this)
        val assigned = AppMonitorService.assignedSlots(this)
        val checks = listOf(
            "App monitoring" to monitoring,
            "Lock overlay" to overlay,
            "HSM detected/connected" to (snapshot.state != SecureVaultUsbManager.UsbState.NO_DEVICE && snapshot.state != SecureVaultUsbManager.UsbState.DISCONNECTED),
            "HSM handshake ready" to snapshot.ready,
            "Hardware slot capacity" to (assigned.size <= snapshot.slotCapacity),
            "Protected applications" to (configured.size <= snapshot.slotCapacity)
        )
        val text = buildString {
            checks.forEach { (name, ok) ->
                append(if (ok) "✓ " else "⚠ ")
                append(name)
                append(if (ok) " — OK\n" else " — Needs attention\n")
            }
            append("\nCurrent HSM state: ${snapshot.state}")
            if (!snapshot.lastError.isNullOrBlank()) append("\nLast HSM error: ${snapshot.lastError}")
        }
        AlertDialog.Builder(this)
            .setTitle("System check")
            .setMessage(text)
            .setPositiveButton("Close", null)
            .show()
    }

    private fun showAboutDialog() {
        AlertDialog.Builder(this)
            .setTitle("About SecureVault")
            .setMessage(
                "SecureVault Locker\n\n" +
                    "Android app protection backed by an ESP32 hardware TOTP authority.\n\n" +
                    "Protocol: SV2\n" +
                    "Hardware slots: up to 8\n" +
                    "Transport: USB serial\n\n" +
                    "TOTP credentials remain on the hardware module and are never generated by the Android app."
            )
            .setPositiveButton("Close", null)
            .show()
    }

    override fun onUsbStateUpdated(state: SecureVaultUsbManager.UsbState) {
        runOnUiThread { refreshUi() }
    }

    override fun onUsbStateChanged(connected: Boolean) = Unit
    override fun onHardwareReady(ready: Boolean) = Unit
    override fun onTotpResult(valid: Boolean, message: String) = Unit
    override fun onHardwareMessage(message: String) = Unit

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_SHORT).show()

    companion object {
        fun isAccessibilityServiceEnabled(context: Context): Boolean {
            val expected = ComponentName(context, AppMonitorService::class.java)
            val enabled = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            ) ?: return false
            return enabled.split(':').any { value ->
                value.equals(expected.flattenToString(), ignoreCase = true) ||
                    value.equals(expected.flattenToShortString(), ignoreCase = true)
            }
        }
    }
}
