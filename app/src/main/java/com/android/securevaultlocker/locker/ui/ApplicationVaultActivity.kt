package com.android.securevaultlocker.locker.ui

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.os.Bundle
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import com.android.securevaultlocker.R
import com.android.securevaultlocker.locker.service.AppMonitorService
import com.android.securevaultlocker.locker.service.SecureVaultUsbManager

/** Application management screen. Each protected application maps to one persistent HSM slot. */
class ApplicationVaultActivity : AppCompatActivity(), SecureVaultUsbManager.Listener {

    private data class AppEntry(
        val packageName: String,
        val label: String,
        val icon: android.graphics.drawable.Drawable,
        var locked: Boolean,
        var slot: Int?
    )

    private val usbManager by lazy { SecureVaultUsbManager.get(this) }
    private val apps = mutableListOf<AppEntry>()
    private val ioExecutor = java.util.concurrent.Executors.newSingleThreadExecutor()
    private val provisionQueue = ArrayDeque<AppEntry>()
    private val removeQueue = ArrayDeque<AppEntry>()
    private var pendingProvision: AppEntry? = null
    private var pendingRemove: AppEntry? = null
    private var bulkOperation = false
    private var appsLoaded = false

    private lateinit var appList: ListView
    private lateinit var adapter: AppAdapter
    private lateinit var tvCount: TextView
    private lateinit var tvLimit: TextView
    private lateinit var tvEmpty: TextView
    private lateinit var masterSwitch: Switch

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContentView(R.layout.activity_application_vault)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.rootLayout)) { v, windowInsets ->
            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(insets.left, insets.top, insets.right, insets.bottom)
            windowInsets
        }

        findViewById<ImageButton>(R.id.btnBack).setOnClickListener { finish() }
        appList = findViewById(R.id.appList)
        tvCount = findViewById(R.id.tvProtectedCount)
        tvLimit = findViewById(R.id.tvSlotLimit)
        tvEmpty = findViewById(R.id.tvEmpty)
        masterSwitch = findViewById(R.id.switchAllApps)
        adapter = AppAdapter()
        appList.adapter = adapter

        findViewById<ImageButton>(R.id.btnRefreshApps).setOnClickListener { loadAppsAsync(force = true) }

        masterSwitch.setOnCheckedChangeListener { _, checked ->
            if (bulkOperation || !appsLoaded) return@setOnCheckedChangeListener
            if (checked) protectAll() else unprotectAll()
        }

        // MainActivity owns the USB connection lifecycle. This screen only observes it.
        usbManager.addListener(this)
        loadAppsAsync(force = true)
    }

    override fun onResume() {
        super.onResume()
        AppMonitorService.loadConfiguredLocks(this)
        if (appsLoaded) syncConfiguredState()
    }

    override fun onDestroy() {
        usbManager.removeListener(this)
        ioExecutor.shutdownNow()
        super.onDestroy()
    }

    /** Loads package metadata and icons away from the UI thread. */
    private fun loadAppsAsync(force: Boolean = false) {
        if (appsLoaded && !force) return
        tvEmpty.visibility = View.GONE
        ioExecutor.execute {
            val loaded = loadAppsFromPackageManager()
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                apps.clear()
                apps.addAll(loaded)
                appsLoaded = true
                updateSummary()
                adapter.notifyDataSetChanged()
                tvEmpty.visibility = if (apps.isEmpty()) View.VISIBLE else View.GONE
                updateMasterSwitch()
            }
        }
    }

    private fun loadAppsFromPackageManager(): List<AppEntry> {
        val pm = packageManager
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolved = pm.queryIntentActivities(launcherIntent, PackageManager.MATCH_ALL)
        val configured = AppMonitorService.configuredSlots(this)
        val assigned = AppMonitorService.assignedSlots(this)

        return resolved.mapNotNull { ri ->
            val ai = ri.activityInfo?.applicationInfo ?: return@mapNotNull null
            val pkg = ai.packageName
            if (pkg == packageName) return@mapNotNull null
            if ((ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0) return@mapNotNull null
            val label = pm.getApplicationLabel(ai).toString().ifBlank { pkg }
            val icon = runCatching { pm.getApplicationIcon(ai) }.getOrNull() ?: return@mapNotNull null
            AppEntry(pkg, label, icon, configured.containsKey(pkg), assigned[pkg])
        }.distinctBy { it.packageName }.sortedBy { it.label.lowercase() }
    }

    private fun syncConfiguredState() {
        val configured = AppMonitorService.configuredSlots(this)
        val assigned = AppMonitorService.assignedSlots(this)
        apps.forEach { entry ->
            entry.slot = assigned[entry.packageName]
            entry.locked = configured.containsKey(entry.packageName)
        }
        updateSummary()
        adapter.notifyDataSetChanged()
        updateMasterSwitch()
    }

    private fun updateSummary() {
        val protectedCount = apps.count { it.locked }
        tvCount.text = "$protectedCount protected"
        val assignedCount = AppMonitorService.assignedSlots(this).size
        tvLimit.text = "$assignedCount / 8 hardware slots assigned"
    }

    private fun updateMasterSwitch() {
        bulkOperation = true
        masterSwitch.isChecked = apps.isNotEmpty() && apps.all { it.locked }
        bulkOperation = false
    }

    private inner class AppAdapter : BaseAdapter() {
        override fun getCount(): Int = apps.size
        override fun getItem(position: Int): AppEntry = apps[position]
        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: android.view.ViewGroup): View {
            val holder: Holder
            val row: LinearLayout
            if (convertView == null) {
                row = LinearLayout(this@ApplicationVaultActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    minimumHeight = dp(56)
                    setPadding(dp(16), dp(8), dp(16), dp(8))
                }
                val icon = ImageView(this@ApplicationVaultActivity).apply {
                    layoutParams = LinearLayout.LayoutParams(dp(36), dp(36)).apply { rightMargin = dp(16) }
                    scaleType = ImageView.ScaleType.CENTER_CROP
                }
                val name = TextView(this@ApplicationVaultActivity).apply {
                    setTextColor(getColor(R.color.sv_text_primary))
                    textSize = 15.5f
                    typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
                    maxLines = 1
                    ellipsize = TextUtils.TruncateAt.END
                }
                val slot = TextView(this@ApplicationVaultActivity).apply {
                    setTextColor(getColor(R.color.sv_cyan))
                    textSize = 9.5f
                    typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
                    setPadding(dp(6), dp(1), dp(6), dp(1))
                    background = getDrawable(R.drawable.bg_slot_badge)
                    visibility = View.GONE
                }
                val textColumn = LinearLayout(this@ApplicationVaultActivity).apply {
                    orientation = LinearLayout.VERTICAL
                    gravity = Gravity.CENTER_VERTICAL
                    layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
                }
                textColumn.addView(name)
                textColumn.addView(slot, LinearLayout.LayoutParams(-2, -2).apply { topMargin = dp(2) })
                val toggle = Switch(this@ApplicationVaultActivity).apply {
                    layoutParams = LinearLayout.LayoutParams(-2, -2)
                }
                row.addView(icon)
                row.addView(textColumn)
                row.addView(toggle)
                holder = Holder(icon, name, slot, toggle)
                row.tag = holder
            } else {
                row = convertView as LinearLayout
                holder = row.tag as Holder
            }

            val entry = getItem(position)
            holder.icon.setImageDrawable(entry.icon)
            holder.name.text = entry.label
            holder.slot.text = if (entry.slot != null) "SLOT ${entry.slot}" else ""
            holder.slot.visibility = if (entry.slot != null) View.VISIBLE else View.GONE
            holder.toggle.setOnCheckedChangeListener(null)
            holder.toggle.isChecked = entry.locked
            holder.toggle.contentDescription = "Protect ${entry.label}"
            holder.toggle.setOnCheckedChangeListener { button, checked ->
                if (checked) enableProtection(entry, button) else disableProtection(entry, button)
            }
            return row
        }
    }

    private data class Holder(
        val icon: ImageView,
        val name: TextView,
        val slot: TextView,
        val toggle: Switch
    )

    private fun enableProtection(entry: AppEntry, toggle: CompoundButton) {
        if (entry.locked) return

        // Re-enabling an application with an existing assignment reuses the same
        // hardware slot and credential. A new slot is created only for a first-time app.
        if (entry.slot != null) {
            AppMonitorService.enableConfiguredLock(this, entry.packageName)
            entry.locked = true
            updateSummary()
            updateMasterSwitch()
            adapter.notifyDataSetChanged()
            toast("${entry.label} re-enabled in HSM Slot ${entry.slot}")
            return
        }

        if (!usbManager.isReady()) {
            resetToggle(toggle, false)
            toast("Connect the SecureVault HSM before creating a hardware slot.")
            return
        }
        if (AppMonitorService.assignedSlots(this).size >= 8) {
            resetToggle(toggle, false)
            toast("All 8 HSM slots are already assigned.")
            return
        }
        pendingProvision = entry
        toast("Creating HSM slot for ${entry.label}…")
        if (!usbManager.provisionSlot(entry.label)) {
            pendingProvision = null
            resetToggle(toggle, false)
        }
    }

    private fun disableProtection(entry: AppEntry, toggle: CompoundButton) {
        if (!entry.locked) return
        // Disabling protection preserves the persistent app -> slot assignment.
        // This makes re-enabling deterministic and avoids unnecessary reprovisioning.
        AppMonitorService.disableConfiguredLock(this, entry.packageName)
        entry.locked = false
        adapter.notifyDataSetChanged()
        updateSummary()
        updateMasterSwitch()
        toast("${entry.label} protection disabled; HSM Slot ${entry.slot} is reserved for re-enable.")
    }

    private fun protectAll() {
        // Re-enable existing assignments first; only then consume genuinely free HSM slots.
        val disabledAssigned = apps.filter { !it.locked && it.slot != null }
        disabledAssigned.forEach {
            AppMonitorService.enableConfiguredLock(this, it.packageName)
            it.locked = true
        }

        val freeHardwareSlots = 8 - AppMonitorService.assignedSlots(this).size
        val newApps = apps.filter { !it.locked && it.slot == null }
        if (newApps.isNotEmpty() && !usbManager.isReady()) {
            bulkOperation = false
            updateSummary(); updateMasterSwitch(); adapter.notifyDataSetChanged()
            toast("Connect the SecureVault HSM before creating new hardware slots.")
            return
        }

        provisionQueue.clear()
        newApps.take(freeHardwareSlots).forEach { provisionQueue.add(it) }
        if (newApps.size > freeHardwareSlots) {
            toast("Only $freeHardwareSlots hardware slots are available. Existing assignments were re-enabled.")
        }
        bulkOperation = provisionQueue.isNotEmpty()
        updateSummary(); adapter.notifyDataSetChanged()
        if (bulkOperation) nextProvision() else updateMasterSwitch()
    }

    private fun nextProvision() {
        if (provisionQueue.isEmpty() || AppMonitorService.assignedSlots(this).size >= 8) {
            bulkOperation = false
            updateSummary()
            updateMasterSwitch()
            adapter.notifyDataSetChanged()
            return
        }
        val next = provisionQueue.removeFirst()
        pendingProvision = next
        if (!usbManager.provisionSlot(next.label)) {
            provisionQueue.clear()
            pendingProvision = null
            bulkOperation = false
            updateSummary(); updateMasterSwitch(); adapter.notifyDataSetChanged()
        }
    }

    private fun unprotectAll() {
        // Do not delete hardware credentials. Protection can be re-enabled later using
        // the exact same persistent application -> slot mapping.
        apps.filter { it.locked }.forEach {
            AppMonitorService.disableConfiguredLock(this, it.packageName)
            it.locked = false
        }
        bulkOperation = false
        updateSummary()
        updateMasterSwitch()
        adapter.notifyDataSetChanged()
    }

    private fun nextRemove() {
        removeQueue.clear()
        pendingRemove = null
        bulkOperation = false
        updateSummary()
        updateMasterSwitch()
        adapter.notifyDataSetChanged()
    }

    override fun onUsbStateChanged(connected: Boolean) {
        if (!connected && (provisionQueue.isNotEmpty() || removeQueue.isNotEmpty())) {
            runOnUiThread {
                provisionQueue.clear(); removeQueue.clear(); pendingProvision = null; pendingRemove = null; bulkOperation = false
                syncConfiguredState()
                toast("Bulk operation stopped because the HSM was disconnected.")
            }
        }
    }

    override fun onHardwareReady(ready: Boolean) = Unit
    override fun onTotpResult(valid: Boolean, message: String) = Unit

    override fun onHardwareMessage(message: String) {
        runOnUiThread {
            when {
                message.startsWith("SLOT_CREATED:") -> {
                    val entry = pendingProvision
                    val slot = message.split(":", limit = 3).getOrNull(1)?.toIntOrNull()
                    if (entry != null && slot != null) {
                        AppMonitorService.saveConfiguredLock(this, entry.packageName, slot)
                        entry.locked = true
                        entry.slot = slot
                        pendingProvision = null
                        if (bulkOperation) nextProvision() else {
                            updateSummary(); updateMasterSwitch(); adapter.notifyDataSetChanged()
                            toast("${entry.label} secured in HSM Slot $slot")
                        }
                    }
                }
                message.startsWith("SLOT_ERROR:") -> {
                    val error = message.substringAfter(':')
                    provisionQueue.clear()
                    pendingProvision = null
                    bulkOperation = false
                    syncConfiguredState()
                    toast(error)
                }
                message.startsWith("SLOT_REMOVED:") -> {
                    val entry = pendingRemove
                    if (entry != null) {
                        AppMonitorService.removeConfiguredLock(this, entry.packageName)
                        entry.locked = false
                        entry.slot = null
                    }
                    pendingRemove = null
                    if (bulkOperation) nextRemove() else {
                        updateSummary(); updateMasterSwitch(); adapter.notifyDataSetChanged()
                        toast("Hardware slot removed")
                    }
                }
            }
        }
    }

    private fun resetToggle(toggle: CompoundButton, checked: Boolean) {
        toggle.setOnCheckedChangeListener(null)
        toggle.isChecked = checked
        val label = toggle.contentDescription?.toString()?.removePrefix("Protect ")
        val entry = apps.firstOrNull { it.label == label }
        toggle.setOnCheckedChangeListener { button, value ->
            if (entry != null) {
                if (value) enableProtection(entry, button) else disableProtection(entry, button)
            }
        }
    }

    private fun setMaster(value: Boolean) {
        bulkOperation = true
        masterSwitch.isChecked = value
        bulkOperation = false
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
