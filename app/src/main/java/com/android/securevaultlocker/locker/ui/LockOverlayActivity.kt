package com.android.securevaultlocker.locker.ui

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.KeyEvent
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.view.animation.AnimationUtils
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.android.securevaultlocker.R
import com.android.securevaultlocker.locker.service.AppMonitorService
import com.android.securevaultlocker.locker.service.SecureVaultUsbManager

/** Full-screen hardware authentication gate for a protected application. */
class LockOverlayActivity : AppCompatActivity(), SecureVaultUsbManager.Listener {
    companion object {
        const val EXTRA_TARGET_PACKAGE = "extra_target_package"
        const val EXTRA_HARDWARE_SLOT = "extra_hardware_slot"
        private const val DEFAULT_TARGET = "com.whatsapp"
    }

    private var targetPackageName = DEFAULT_TARGET
    private var hardwareSlot = -1

    private lateinit var tvPackageName: TextView
    private lateinit var tvHardwareStatus: TextView
    private lateinit var etTotpCode: EditText
    private lateinit var btnUnlock: Button
    private lateinit var tvStatus: TextView

    private val usbManager by lazy { SecureVaultUsbManager.get(this) }
    private val mainHandler = Handler(Looper.getMainLooper())
    private var unlockRequestInFlight = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_lock_overlay)
        extractTarget(intent)
        bindViews()
        setupListeners()
        setupBackPressInterception()
        // Authentication overlay observes the already-owned shared USB session.
        // It must never initiate USB discovery or permission requests.
        usbManager.addListener(this)
        etTotpCode.requestFocus()
        mainHandler.postDelayed({
            (getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager)
                .showSoftInput(etTotpCode, InputMethodManager.SHOW_IMPLICIT)
        }, 250)
    }

    override fun onDestroy() {
        usbManager.removeListener(this)
        super.onDestroy()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        extractTarget(intent)
        updateTargetDisplay()
        etTotpCode.text?.clear()
        unlockRequestInFlight = false
    }

    private fun extractTarget(intent: Intent?) {
        targetPackageName = intent?.getStringExtra(EXTRA_TARGET_PACKAGE) ?: DEFAULT_TARGET
        hardwareSlot = intent?.getIntExtra(EXTRA_HARDWARE_SLOT, -1) ?: -1
    }

    private fun bindViews() {
        tvPackageName = findViewById(R.id.tvPackageName)
        tvHardwareStatus = findViewById(R.id.tvHardwareStatus)
        etTotpCode = findViewById(R.id.etTotpCode)
        btnUnlock = findViewById(R.id.btnUnlock)
        tvStatus = findViewById(R.id.tvStatus)
        updateTargetDisplay()
    }

    private fun updateTargetDisplay() {
        val friendly = try {
            val info = packageManager.getApplicationInfo(targetPackageName, 0)
            packageManager.getApplicationLabel(info).toString()
        } catch (_: PackageManager.NameNotFoundException) { targetPackageName }
        tvPackageName.text = friendly
    }

    private fun setupListeners() {
        btnUnlock.setOnClickListener { handleUnlockAttempt() }
        etTotpCode.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                tvStatus.visibility = View.GONE
                if (s?.length == 6) handleUnlockAttempt()
            }
            override fun afterTextChanged(s: Editable?) = Unit
        })
        etTotpCode.setOnEditorActionListener { _, _, event ->
            if (event?.keyCode == KeyEvent.KEYCODE_ENTER) { handleUnlockAttempt(); true } else false
        }
    }

    private fun setupBackPressInterception() {
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                startActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                finish()
            }
        })
    }

    private fun handleUnlockAttempt() {
        if (unlockRequestInFlight) return
        val code = etTotpCode.text?.toString()?.trim() ?: ""
        if (code.length != 6 || !code.all(Char::isDigit)) {
            showErrorFeedback(getString(R.string.error_code_too_short)); return
        }
        if (hardwareSlot <= 0) {
            showErrorFeedback("This app has no SecureVault hardware slot."); return
        }
        if (!usbManager.isReady()) {
            showErrorFeedback(getString(R.string.error_hardware_not_ready)); return
        }
        unlockRequestInFlight = true
        tvStatus.text = getString(R.string.verifying_with_hardware)
        tvStatus.setTextColor(getColor(R.color.sv_cyan))
        tvStatus.visibility = View.VISIBLE
        usbManager.verifyTotp(hardwareSlot, code)
    }

    override fun onUsbStateChanged(connected: Boolean) {
        runOnUiThread {
            tvHardwareStatus.text = if (connected) getString(R.string.hardware_connecting) else getString(R.string.hardware_disconnected)
        }
    }

    override fun onHardwareReady(ready: Boolean) {
        runOnUiThread {
            tvHardwareStatus.text = if (ready) getString(R.string.hardware_ready) else getString(R.string.hardware_connecting)
            if (ready && hardwareSlot > 0) {
                usbManager.selectSlot(hardwareSlot)
            }
        }
    }

    override fun onTotpResult(valid: Boolean, message: String) {
        runOnUiThread {
            unlockRequestInFlight = false
            if (valid) {
                AppMonitorService.grantGracePeriod(targetPackageName)
                launchTargetApplication()
            } else {
                showErrorFeedback(getString(R.string.error_invalid_totp))
                etTotpCode.text?.clear()
            }
        }
    }

    override fun onHardwareMessage(message: String) {
        runOnUiThread {
            if (message.startsWith("TOTP_RATE_LOCKED:")) {
                unlockRequestInFlight = false
                val seconds = message.substringAfter(':').toIntOrNull() ?: 15
                showErrorFeedback("Too many incorrect codes. Try again in ${seconds}s.")
                etTotpCode.text?.clear()
            }
        }
    }

    private fun launchTargetApplication() {
        val launchIntent = packageManager.getLaunchIntentForPackage(targetPackageName)
        if (launchIntent != null) {
            launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            startActivity(launchIntent)
        }
        finishAndRemoveTask()
    }

    private fun showErrorFeedback(message: String) {
        tvStatus.text = message
        tvStatus.setTextColor(getColor(R.color.sv_error))
        tvStatus.visibility = View.VISIBLE
        try { etTotpCode.startAnimation(AnimationUtils.loadAnimation(this, android.R.anim.fade_in)) } catch (_: Exception) {}
    }
}
