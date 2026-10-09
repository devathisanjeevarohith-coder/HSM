package com.android.securevaultlocker.locker.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import com.android.securevaultlocker.R
import com.android.securevaultlocker.locker.service.AppMonitorService
import com.android.securevaultlocker.locker.service.SecureVaultUsbManager

/** Clean SecureVault home dashboard. Application selection lives in ApplicationVaultActivity. */
class MainActivity : AppCompatActivity(), SecureVaultUsbManager.Listener {

    private val usbManager by lazy { SecureVaultUsbManager.get(this) }
    private lateinit var tvUsbStatus: TextView
    private lateinit var tvUsbDetail: TextView
    private lateinit var tvProtectedCount: TextView
    private lateinit var tvSlotCount: TextView
    private lateinit var btnRetryUsb: Button
    private lateinit var tvMonitoringStatus: TextView
    private lateinit var tvOverlayStatus: TextView
    private lateinit var tvHomeHsmStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContentView(R.layout.activity_main)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.rootLayout)) { v, windowInsets ->
            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(insets.left, insets.top, insets.right, insets.bottom)
            windowInsets
        }

        bindViews()
        refreshSummary()

        usbManager.addListener(this)

        findViewById<ImageButton>(R.id.btnSettings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        btnRetryUsb.setOnClickListener {
            usbManager.connectByUserRequest()
        }

        findViewById<View>(R.id.btnOpenVault).setOnClickListener {
            startActivity(Intent(this, ApplicationVaultActivity::class.java))
        }
        findViewById<ImageButton>(R.id.btnRefresh).setOnClickListener {
            refreshSummary()
            AppMonitorService.loadConfiguredLocks(this)
            usbManager.reconnectByUserRequest()
            toast("SecureVault refreshed")
        }
    }

    override fun onStart() {
        super.onStart()
        usbManager.start()
    }

    override fun onResume() {
        super.onResume()
        AppMonitorService.loadConfiguredLocks(this)
        refreshSummary()
    }

    override fun onDestroy() {
        usbManager.removeListener(this)
        super.onDestroy()
    }

    private fun bindViews() {
        tvUsbStatus = findViewById(R.id.tvUsbStatus)
        tvUsbDetail = findViewById(R.id.tvUsbDetail)
        tvProtectedCount = findViewById(R.id.tvProtectedCount)
        tvSlotCount = findViewById(R.id.tvSlotCount)
        btnRetryUsb = findViewById(R.id.btnRetryUsb)
        tvMonitoringStatus = findViewById(R.id.tvMonitoringStatus)
        tvOverlayStatus = findViewById(R.id.tvOverlayStatus)
        tvHomeHsmStatus = findViewById(R.id.tvHomeHsmStatus)
    }

    private fun refreshSummary() {
        val configured = AppMonitorService.configuredSlots(this)
        tvProtectedCount.text = configured.size.toString()
        tvSlotCount.text = configured.size.toString()
        val monitoringEnabled = SettingsActivity.isAccessibilityServiceEnabled(this)
        val overlayEnabled = android.provider.Settings.canDrawOverlays(this)
        tvMonitoringStatus.text = if (monitoringEnabled) "Enabled" else "Not enabled"
        tvMonitoringStatus.setTextColor(getColor(if (monitoringEnabled) R.color.sv_success else R.color.sv_warning))
        tvOverlayStatus.text = if (overlayEnabled) "Enabled" else "Not enabled"
        tvOverlayStatus.setTextColor(getColor(if (overlayEnabled) R.color.sv_success else R.color.sv_warning))
        val hsmReady = usbManager.isReady()
        val hsmConnected = usbManager.isConnected()
        tvHomeHsmStatus.text = when { hsmReady -> "Ready"; hsmConnected -> "Connecting"; else -> "Not connected" }
        tvHomeHsmStatus.setTextColor(getColor(when { hsmReady -> R.color.sv_success; hsmConnected -> R.color.sv_warning; else -> R.color.sv_text_muted }))
    }

    override fun onUsbStateUpdated(state: SecureVaultUsbManager.UsbState) {
        runOnUiThread {
            when (state) {
                SecureVaultUsbManager.UsbState.NO_DEVICE -> {
                    tvUsbStatus.text = "ESP32 not detected"
                    tvUsbStatus.setTextColor(getColor(R.color.sv_error))
                    tvUsbDetail.text = "Connect the SecureVault ESP32 module using a USB OTG adapter."
                    btnRetryUsb.text = "Connect ESP32"
                    btnRetryUsb.visibility = View.VISIBLE
                }
                SecureVaultUsbManager.UsbState.DEVICE_DETECTED,
                SecureVaultUsbManager.UsbState.PERMISSION_REQUIRED -> {
                    tvUsbStatus.text = "ESP32 detected — permission required"
                    tvUsbStatus.setTextColor(getColor(R.color.sv_warning))
                    tvUsbDetail.text = "Tap 'Connect ESP32' to grant permission for the detected ESP32."
                    btnRetryUsb.text = "Connect ESP32"
                    btnRetryUsb.visibility = View.VISIBLE
                }
                SecureVaultUsbManager.UsbState.PERMISSION_REQUESTED -> {
                    tvUsbStatus.text = "Waiting for USB permission..."
                    tvUsbStatus.setTextColor(getColor(R.color.sv_warning))
                    tvUsbDetail.text = "Please respond to the Android USB permission prompt."
                    btnRetryUsb.visibility = View.GONE
                }
                SecureVaultUsbManager.UsbState.CONNECTING -> {
                    tvUsbStatus.text = "Connecting to ESP32..."
                    tvUsbStatus.setTextColor(getColor(R.color.sv_warning))
                    tvUsbDetail.text = "Physical module detected • establishing secure session with ESP32..."
                    btnRetryUsb.visibility = View.GONE
                }
                SecureVaultUsbManager.UsbState.HANDSHAKING -> {
                    tvUsbStatus.text = "Initializing SecureVault..."
                    tvUsbStatus.setTextColor(getColor(R.color.sv_warning))
                    tvUsbDetail.text = "Performing hardware handshake and time synchronization..."
                    btnRetryUsb.visibility = View.GONE
                }
                SecureVaultUsbManager.UsbState.READY -> {
                    tvUsbStatus.text = "ESP32 Connected"
                    tvUsbStatus.setTextColor(getColor(R.color.sv_success))
                    tvUsbDetail.text = "SecureVault HSM is online and authenticating protected applications."
                    btnRetryUsb.visibility = View.GONE
                }
                SecureVaultUsbManager.UsbState.PERMISSION_DENIED -> {
                    tvUsbStatus.text = "Permission denied"
                    tvUsbStatus.setTextColor(getColor(R.color.sv_error))
                    tvUsbDetail.text = "USB permission was denied. Tap 'Connect ESP32' to prompt again."
                    btnRetryUsb.text = "Connect ESP32"
                    btnRetryUsb.visibility = View.VISIBLE
                }
                SecureVaultUsbManager.UsbState.ERROR -> {
                    tvUsbStatus.text = "Connection failed — Reconnect"
                    tvUsbStatus.setTextColor(getColor(R.color.sv_error))
                    tvUsbDetail.text = "An error occurred with the USB connection. Tap 'Reconnect ESP32'."
                    btnRetryUsb.text = "Reconnect ESP32"
                    btnRetryUsb.visibility = View.VISIBLE
                }
                SecureVaultUsbManager.UsbState.DISCONNECTED -> {
                    tvUsbStatus.text = "ESP32 disconnected — Reconnect"
                    tvUsbStatus.setTextColor(getColor(R.color.sv_error))
                    tvUsbDetail.text = "Connect the SecureVault module by USB to authenticate protected apps."
                    btnRetryUsb.text = "Reconnect ESP32"
                    btnRetryUsb.visibility = View.VISIBLE
                }
            }
        }
    }

    override fun onUsbStateChanged(connected: Boolean) = Unit
    override fun onHardwareReady(ready: Boolean) = Unit
    override fun onTotpResult(valid: Boolean, message: String) = Unit
    override fun onHardwareMessage(message: String) = Unit

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
}
