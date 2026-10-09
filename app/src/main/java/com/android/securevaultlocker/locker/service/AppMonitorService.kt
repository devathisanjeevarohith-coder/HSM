package com.android.securevaultlocker.locker.service

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.content.Intent
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import com.android.securevaultlocker.locker.ui.LockOverlayActivity
import java.util.concurrent.ConcurrentHashMap

/** Enforces the hardware-backed lock for the apps selected in SecureVault. */
class AppMonitorService : AccessibilityService(), SecureVaultUsbManager.Listener {

    companion object {
        private const val TAG = "AppMonitorService"
        private const val PREFS = "securevault_apps"
        private const val KEY_PREFIX = "slot_"
        private const val ENABLED_PREFIX = "enabled_"

        // Short launch grace prevents Android from immediately relaunching the overlay
        // while the authenticated target application is being brought to the foreground.
        const val DEFAULT_GRACE_PERIOD_MS: Long = 15_000L

        val lockedPackages: MutableSet<String> = ConcurrentHashMap.newKeySet()
        val unlockedSessions = ConcurrentHashMap<String, Long>()

        fun loadConfiguredLocks(context: Context) {
            lockedPackages.clear()
            configuredSlots(context).keys.forEach { lockedPackages.add(it) }
        }

        /** Active application -> hardware slot mappings. */
        fun configuredSlots(context: Context): Map<String, Int> {
            val prefs = context.getSharedPreferences(PREFS, MODE_PRIVATE)
            return prefs.all.mapNotNull { (key, value) ->
                if (key.startsWith(KEY_PREFIX) && value is Int) {
                    val pkg = key.removePrefix(KEY_PREFIX)
                    val enabled = prefs.getBoolean(ENABLED_PREFIX + pkg, true)
                    if (enabled) pkg to value else null
                } else null
            }.toMap()
        }

        /** All persistent application -> hardware slot assignments, including disabled apps. */
        fun assignedSlots(context: Context): Map<String, Int> {
            val prefs = context.getSharedPreferences(PREFS, MODE_PRIVATE)
            return prefs.all.mapNotNull { (key, value) ->
                if (key.startsWith(KEY_PREFIX) && value is Int && value > 0) {
                    key.removePrefix(KEY_PREFIX) to value
                } else null
            }.toMap()
        }

        fun saveConfiguredLock(context: Context, packageName: String, slot: Int) {
            context.getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putInt(KEY_PREFIX + packageName, slot)
                .putBoolean(ENABLED_PREFIX + packageName, true)
                .apply()
            lockedPackages.add(packageName)
        }

        /** Disables protection but deliberately preserves the slot mapping for re-enable. */
        fun disableConfiguredLock(context: Context, packageName: String) {
            context.getSharedPreferences(PREFS, MODE_PRIVATE)
                .edit().putBoolean(ENABLED_PREFIX + packageName, false).apply()
            lockedPackages.remove(packageName)
            unlockedSessions.remove(packageName)
        }

        fun enableConfiguredLock(context: Context, packageName: String) {
            if (!assignedSlots(context).containsKey(packageName)) return
            context.getSharedPreferences(PREFS, MODE_PRIVATE)
                .edit().putBoolean(ENABLED_PREFIX + packageName, true).apply()
            lockedPackages.add(packageName)
        }

        /** Explicitly deletes the persistent hardware assignment. */
        fun removeConfiguredLock(context: Context, packageName: String) {
            context.getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .remove(KEY_PREFIX + packageName)
                .remove(ENABLED_PREFIX + packageName)
                .apply()
            lockedPackages.remove(packageName)
            unlockedSessions.remove(packageName)
        }

        fun slotForPackage(context: Context, packageName: String): Int? =
            configuredSlots(context)[packageName]

        fun grantGracePeriod(packageName: String, durationMs: Long = DEFAULT_GRACE_PERIOD_MS) {
            unlockedSessions[packageName] = System.currentTimeMillis() + durationMs
        }

        fun isSessionValid(packageName: String): Boolean {
            val expiry = unlockedSessions[packageName] ?: return false
            if (System.currentTimeMillis() < expiry) return true
            unlockedSessions.remove(packageName)
            return false
        }

        fun revokeSession(packageName: String) { unlockedSessions.remove(packageName) }

        fun revokeAllSessions() { unlockedSessions.clear() }
    }

    private val usbManager by lazy { SecureVaultUsbManager.get(this) }
    private var lastForegroundPackage: String? = null

    override fun onServiceConnected() {
        super.onServiceConnected()
        Log.d(TAG, "APP_MONITOR_STARTED")
        loadConfiguredLocks(this)
        usbManager.addListener(this)
        Log.i(TAG, "SecureVault monitor connected. Protected apps: ${lockedPackages.size}")
    }

    override fun onDestroy() {
        Log.d(TAG, "APP_MONITOR_STOPPED")
        usbManager.removeListener(this)
        revokeAllSessions()
        super.onDestroy()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event?.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return
        val pkg = event.packageName?.toString() ?: return

        if (lastForegroundPackage != null && lastForegroundPackage != pkg) {
            revokeSession(lastForegroundPackage!!)
        }
        lastForegroundPackage = pkg

        if (pkg == applicationContext.packageName) return
        if (!lockedPackages.contains(pkg)) return
        if (isSessionValid(pkg)) return

        val slot = slotForPackage(this, pkg) ?: return
        launchLockOverlay(pkg, slot)
    }

    private fun launchLockOverlay(targetPackage: String, slot: Int) {
        val intent = Intent(this, LockOverlayActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(LockOverlayActivity.EXTRA_TARGET_PACKAGE, targetPackage)
            putExtra(LockOverlayActivity.EXTRA_HARDWARE_SLOT, slot)
        }
        startActivity(intent)
    }

    override fun onInterrupt() { Log.w(TAG, "Accessibility service interrupted") }

    override fun onUsbStateChanged(connected: Boolean) {
        if (!connected) revokeAllSessions()
    }

    override fun onHardwareReady(ready: Boolean) {
        if (!ready) revokeAllSessions()
    }

    override fun onTotpResult(valid: Boolean, message: String) = Unit
    override fun onHardwareMessage(message: String) = Unit
}
