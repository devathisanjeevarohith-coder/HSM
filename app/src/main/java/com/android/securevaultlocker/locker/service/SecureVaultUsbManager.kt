package com.android.securevaultlocker.locker.service

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.util.Log
import com.hoho.android.usbserial.driver.UsbSerialDriver
import com.hoho.android.usbserial.driver.UsbSerialPort
import com.hoho.android.usbserial.driver.UsbSerialProber
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Single authoritative USB transport/state manager for the SecureVault HSM.
 *
 * Important invariants:
 *  - start() only observes USB state; it never tears down an existing session.
 *  - Every user-initiated connect/reconnect creates a new session generation.
 *    Queued work from an older generation is discarded rather than sent to a new session.
 *  - Android enforces a command gap slightly larger than the firmware's 180 ms limiter.
 *  - The HSM is considered usable only after TIME_SYNCED.
 *  - The selected hardware slot is confirmed by the HSM's SLOT_SELECTED response.
 */
class SecureVaultUsbManager private constructor(context: Context) {

    enum class UsbState {
        NO_DEVICE,
        DEVICE_DETECTED,
        PERMISSION_REQUIRED,
        PERMISSION_REQUESTED,
        CONNECTING,
        HANDSHAKING,
        READY,
        DISCONNECTED,
        PERMISSION_DENIED,
        ERROR
    }

    interface Listener {
        fun onUsbStateChanged(connected: Boolean)
        fun onHardwareReady(ready: Boolean)
        fun onTotpResult(valid: Boolean, message: String)
        fun onHardwareMessage(message: String)
        fun onUsbStateUpdated(state: UsbState) {}
    }

    private enum class HandshakePhase {
        IDLE,
        WAITING_FOR_HOST_READY,
        WAITING_FOR_TIME_SYNC,
        READY
    }

    companion object {
        private const val TAG = "SecureVaultUsb"
        private const val ACTION_USB_PERMISSION = "com.android.securevaultlocker.USB_PERMISSION"
        private const val BAUD_RATE = 115200
        private const val READ_TIMEOUT_MS = 500
        private const val HEARTBEAT_INTERVAL_MS = 2000L
        private const val PERMISSION_TIMEOUT_MS = 8000L
        private const val HANDSHAKE_TIMEOUT_MS = 7000L
        private const val SERIAL_BOOT_SETTLE_MS = 1200L

        // Firmware RATE_LIMIT_MS is 180 ms. Keep a margin on the Android side so
        // all normal commands are paced before they reach the ESP32.
        private const val MIN_COMMAND_GAP_MS = 220L
        private const val HANDSHAKE_RETRY_DELAY_MS = 450L
        private const val TIME_SYNC_DELAY_MS = 450L
        private const val SESSION_RESTART_DELAY_MS = 250L

        // The hardware used by the project is a CP210x ESP32 USB-serial interface.
        // Prefer its known VID/PID when several USB serial devices are present,
        // while retaining a fallback so other compatible boards still work.
        private const val ESP32_VENDOR_ID = 0x10C4
        private const val ESP32_PRODUCT_ID = 0xEA60

        @Volatile private var instance: SecureVaultUsbManager? = null

        fun get(context: Context): SecureVaultUsbManager =
            instance ?: synchronized(this) {
                instance ?: SecureVaultUsbManager(context.applicationContext).also { instance = it }
            }
    }

    private val appContext = context.applicationContext
    private val usbManager = appContext.getSystemService(Context.USB_SERVICE) as UsbManager
    private val listeners = mutableSetOf<Listener>()
    private val ioExecutor = Executors.newSingleThreadExecutor()
    private val writeExecutor = Executors.newSingleThreadExecutor()
    private val scheduler = Executors.newSingleThreadScheduledExecutor()
    private val readExecutor = Executors.newSingleThreadExecutor()
    private val diagnosticLogger = SecureVaultDiagnosticLogger(appContext)

    private var port: UsbSerialPort? = null
    private var driver: UsbSerialDriver? = null
    private var readTask: Future<*>? = null
    private var heartbeatTask: ScheduledFuture<*>? = null
    private var permissionTimeoutFuture: ScheduledFuture<*>? = null
    private var handshakeTimeoutFuture: ScheduledFuture<*>? = null
    private var helloFuture: ScheduledFuture<*>? = null
    private var handshakeRetryFuture: ScheduledFuture<*>? = null
    private var timeSyncFuture: ScheduledFuture<*>? = null
    private var receiverRegistered = false

    @Volatile private var permissionTransactionId: Long = 0L
    @Volatile private var permissionGeneration: Long = 0L
    @Volatile private var ready = false
    @Volatile private var connected = false
    @Volatile private var sessionGeneration: Long = 0L
    @Volatile private var handshakePhase = HandshakePhase.IDLE
    @Volatile private var selectedSlot: Int? = null
    @Volatile private var requestedSlot: Int? = null
    @Volatile private var firmwareVersion: String = "Unknown"
    @Volatile private var transportInfo: String = "USB Serial"
    @Volatile private var securityInfo: String = "ESP32 hardware authority"
    @Volatile private var slotCapacity: Int = 8
    @Volatile private var lastProtocolEvent: String = "No HSM response yet"
    @Volatile private var lastError: String? = null

    private var receiveBuffer = StringBuilder()

    // Accessed only by writeExecutor, so no additional synchronization is needed.
    private var lastCommandWriteAtMs = 0L

    @Volatile
    var currentState: UsbState = UsbState.DISCONNECTED
        private set

    init {
        registerReceiverOnce()
    }

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                ACTION_USB_PERMISSION -> handlePermissionResult(intent)
                UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                    val device = getUsbDevice(intent) ?: return
                    Log.d(
                        TAG,
                        "USB_DEVICE_ATTACHED: id=${device.deviceId} vid=${device.vendorId} pid=${device.productId} name=${device.deviceName}"
                    )
                    diagnosticLogger.log(
                        "USB",
                        "device attached id=${device.deviceId} vid=${device.vendorId} pid=${device.productId}"
                    )
                    // Never overwrite an active READY/HANDSHAKING/CONNECTING state.
                    if (!connected && currentState !in setOf(
                            UsbState.CONNECTING,
                            UsbState.HANDSHAKING,
                            UsbState.PERMISSION_REQUESTED
                        )
                    ) {
                        setState(UsbState.DEVICE_DETECTED)
                    }
                }
                UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                    val device = getUsbDevice(intent)
                    Log.d(TAG, "USB_DEVICE_DETACHED: id=${device?.deviceId}")
                    diagnosticLogger.log("USB", "device detached id=${device?.deviceId}")
                    close("USB device detached")
                }
            }
        }
    }

    private fun handlePermissionResult(intent: Intent) {
        val txId = intent.getLongExtra("tx_id", 0L)
        val generation = intent.getLongExtra("generation", 0L)
        val device = getUsbDevice(intent) ?: findEsp32Device()
        val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)

        Log.d(TAG, "USB_PERMISSION_RESULT: granted=$granted txId=$txId generation=$generation")
        diagnosticLogger.log(
            "PERMISSION",
            "result granted=$granted tx=$txId generation=$generation deviceId=${device?.deviceId}"
        )

        synchronized(this) {
            if (permissionTransactionId == 0L ||
                permissionTransactionId != txId ||
                permissionGeneration != sessionGeneration ||
                generation != sessionGeneration
            ) {
                Log.w(TAG, "USB_STALE_PERMISSION_RESULT ignored tx=$txId generation=$generation currentTx=$permissionTransactionId currentGeneration=$sessionGeneration")
                diagnosticLogger.log("PERMISSION", "stale result ignored tx=$txId generation=$generation currentGeneration=$sessionGeneration")
                return
            }
            clearPermissionTransactionInternal()
        }

        if (device == null) {
            lastError = "USB permission returned without a device"
            setState(UsbState.ERROR)
            return
        }

        if (granted) {
            Log.d(TAG, "USB_PERMISSION_GRANTED")
            setState(UsbState.CONNECTING)
            openDevice(device, sessionGeneration)
        } else {
            Log.d(TAG, "USB_PERMISSION_DENIED")
            setState(UsbState.PERMISSION_DENIED)
        }
    }

    fun addListener(listener: Listener) {
        synchronized(listeners) { listeners.add(listener) }
        listener.onUsbStateChanged(connected)
        listener.onHardwareReady(ready)
        listener.onUsbStateUpdated(currentState)
    }

    fun removeListener(listener: Listener) {
        synchronized(listeners) { listeners.remove(listener) }
    }

    /**
     * Lifecycle observation only. It must never replace an active state with DEVICE_DETECTED.
     * Explicit user connection is handled by connectByUserRequest().
     */
    fun start() {
        Log.d(TAG, "USB_START")
        diagnosticLogger.log("LIFECYCLE", "USB manager observing current USB state")

        synchronized(this) {
            if (connected || ready || currentState == UsbState.CONNECTING ||
                currentState == UsbState.HANDSHAKING || currentState == UsbState.PERMISSION_REQUESTED
            ) {
                Log.d(TAG, "USB_START ignored: active session/state=${currentState} connected=$connected ready=$ready")
                return
            }
        }

        val device = findEsp32Device()
        if (device == null) {
            setState(UsbState.NO_DEVICE)
            return
        }

        val nextState = if (usbManager.hasPermission(device)) {
            UsbState.DEVICE_DETECTED
        } else {
            UsbState.PERMISSION_REQUIRED
        }
        Log.d(
            TAG,
            "USB_DEVICE_AVAILABLE: id=${device.deviceId} vid=${device.vendorId} pid=${device.productId} permission=${usbManager.hasPermission(device)}"
        )
        diagnosticLogger.log(
            "USB",
            "device available id=${device.deviceId} vid=${device.vendorId} pid=${device.productId} permission=${usbManager.hasPermission(device)}"
        )
        setState(nextState)
    }

    /** Explicit user action from Home. */
    fun connectByUserRequest() = resetAndRetryConnection()

    /** Explicit user action from Settings. */
    fun reconnectByUserRequest() = resetAndRetryConnection()

    /**
     * Recreates the Android-side USB session deterministically. Existing queued work from
     * previous attempts is invalidated by the session generation counter.
     */
    fun resetAndRetryConnection() {
        Log.d(TAG, "USB_RESET_CONNECTION")
        diagnosticLogger.log("USB", "user requested connection/reconnection")

        val generation = synchronized(this) {
            sessionGeneration += 1L
            clearPermissionTransactionInternal()
            closeInternal("Reset and retry connection")
            lastError = null
            setState(UsbState.CONNECTING)
            sessionGeneration
        }

        ioExecutor.execute {
            if (generation != sessionGeneration) return@execute

            val device = findEsp32Device()
            if (device == null) {
                setState(UsbState.NO_DEVICE)
                return@execute
            }

            Log.d(
                TAG,
                "USB_DEVICE_SELECTED: id=${device.deviceId} vid=${device.vendorId} pid=${device.productId} name=${device.deviceName} generation=$generation"
            )
            diagnosticLogger.log(
                "USB",
                "selected id=${device.deviceId} vid=${device.vendorId} pid=${device.productId} generation=$generation"
            )

            if (usbManager.hasPermission(device)) {
                setState(UsbState.CONNECTING)
                openDevice(device, generation)
            } else {
                setState(UsbState.PERMISSION_REQUIRED)
                requestPermission(device, generation)
            }
        }
    }

    fun disconnect(reason: String = "User requested disconnect") {
        ioExecutor.execute {
            synchronized(this) {
                sessionGeneration += 1L
                clearPermissionTransactionInternal()
                closeInternal(reason)
            }
            setState(UsbState.DISCONNECTED)
            Log.d(TAG, "USB_DISCONNECTED: $reason")
        }
    }

    fun isReady(): Boolean = ready
    fun isConnected(): Boolean = connected
    fun getState(): UsbState = currentState

    /** Sends SELECT_SLOT and waits for the HSM's SLOT_SELECTED acknowledgement. */
    fun selectSlot(slot: Int): Boolean {
        if (!ready || slot <= 0 || slot > slotCapacity) return false
        requestedSlot = slot
        selectedSlot = null
        val generation = sessionGeneration
        writeLine("SELECT_SLOT:$slot", generation)
        return true
    }

    /** Verification is accepted only for the confirmed selected hardware slot. */
    fun verifyTotp(slot: Int, code: String): Boolean {
        val normalized = code.trim()
        if (!ready || slot <= 0 || slot > slotCapacity || selectedSlot != slot ||
            normalized.length != 6 || !normalized.all(Char::isDigit)
        ) {
            return false
        }
        writeLine("VERIFY_TOTP:$slot:$normalized", sessionGeneration)
        return true
    }

    fun provisionSlot(appName: String): Boolean {
        if (!ready) return false
        val safeName = appName
            .replace(':', '_')
            .replace('|', '_')
            .replace('\n', ' ')
            .replace('\r', ' ')
            .trim()
            .take(24)
        if (safeName.isBlank()) return false
        writeLine("PROVISION_AUTO:$safeName", sessionGeneration)
        return true
    }

    fun removeSlot(slot: Int): Boolean {
        if (!ready || slot <= 0 || slot > slotCapacity) return false
        writeLine("REMOVE_SLOT:$slot", sessionGeneration)
        return true
    }

    fun requestSlots() {
        if (ready) writeLine("GET_SLOTS", sessionGeneration)
    }

    data class HsmSnapshot(
        val state: UsbState,
        val connected: Boolean,
        val ready: Boolean,
        val firmwareVersion: String,
        val transport: String,
        val security: String,
        val slotCapacity: Int,
        val selectedSlot: Int?,
        val lastProtocolEvent: String,
        val lastError: String?
    )

    fun snapshot(): HsmSnapshot = HsmSnapshot(
        currentState,
        connected,
        ready,
        firmwareVersion,
        transportInfo,
        securityInfo,
        slotCapacity,
        selectedSlot,
        lastProtocolEvent,
        lastError
    )

    fun diagnosticLog(): String = diagnosticLogger.getLogContent()
    fun exportDiagnosticIntent(context: Context): Intent? = diagnosticLogger.getShareIntent(context)
    fun clearDiagnosticLog() = diagnosticLogger.clearLogs()

    private fun registerReceiverOnce() {
        synchronized(this) {
            if (receiverRegistered) return
            val filter = IntentFilter().apply {
                addAction(ACTION_USB_PERMISSION)
                addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
                addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
            }
            if (Build.VERSION.SDK_INT >= 33) {
                appContext.registerReceiver(usbReceiver, filter, Context.RECEIVER_EXPORTED)
            } else {
                @Suppress("DEPRECATION")
                appContext.registerReceiver(usbReceiver, filter)
            }
            receiverRegistered = true
        }
    }

    private fun getUsbDevice(intent: Intent): UsbDevice? = if (Build.VERSION.SDK_INT >= 33) {
        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
    } else {
        @Suppress("DEPRECATION")
        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
    }

    private fun findEsp32Device(): UsbDevice? {
        val drivers = runCatching {
            UsbSerialProber.getDefaultProber().findAllDrivers(usbManager)
        }.getOrElse {
            diagnosticLogger.log("USB", "serial probe failed: ${it.message}")
            Log.e(TAG, "USB serial probe failed", it)
            emptyList()
        }
        Log.d(TAG, "USB_DEVICES_FOUND:${drivers.size}")

        return drivers.firstOrNull {
            it.device.vendorId == ESP32_VENDOR_ID && it.device.productId == ESP32_PRODUCT_ID
        }?.device ?: drivers.firstOrNull()?.device
    }

    private fun requestPermission(device: UsbDevice, generation: Long) {
        val txId = System.currentTimeMillis()
        synchronized(this) {
            if (generation != sessionGeneration) return
            permissionTransactionId = txId
            permissionGeneration = generation
            setState(UsbState.PERMISSION_REQUESTED)
        }

        Log.d(TAG, "USB_PERMISSION_REQUESTED: txId=$txId generation=$generation deviceId=${device.deviceId}")
        diagnosticLogger.log(
            "PERMISSION",
            "requested tx=$txId generation=$generation deviceId=${device.deviceId} vid=${device.vendorId} pid=${device.productId}"
        )

        permissionTimeoutFuture?.cancel(true)
        permissionTimeoutFuture = scheduler.schedule({
            synchronized(this) {
                if (permissionTransactionId != txId ||
                    permissionGeneration != sessionGeneration ||
                    generation != sessionGeneration
                ) return@schedule

                clearPermissionTransactionInternal()
                val dev = findEsp32Device()
                if (dev != null && usbManager.hasPermission(dev)) {
                    Log.d(TAG, "USB_PERMISSION_ALREADY_GRANTED after timeout; continuing")
                    setState(UsbState.CONNECTING)
                    openDevice(dev, generation)
                } else {
                    Log.d(TAG, "USB_PERMISSION_TIMEOUT")
                    setState(UsbState.PERMISSION_REQUIRED)
                }
            }
        }, PERMISSION_TIMEOUT_MS, TimeUnit.MILLISECONDS)

        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }

        val permissionIntent = Intent(ACTION_USB_PERMISSION).apply {
            setPackage(appContext.packageName)
            putExtra("tx_id", txId)
            putExtra("generation", generation)
        }

        val pending = PendingIntent.getBroadcast(
            appContext,
            (device.deviceId * 31 + (txId % 10000).toInt()),
            permissionIntent,
            flags
        )
        usbManager.requestPermission(device, pending)
    }

    private fun clearPermissionTransactionInternal() {
        permissionTransactionId = 0L
        permissionGeneration = 0L
        permissionTimeoutFuture?.cancel(true)
        permissionTimeoutFuture = null
    }

    private fun openDevice(device: UsbDevice, generation: Long) {
        ioExecutor.execute {
            if (generation != sessionGeneration) return@execute

            try {
                synchronized(this) {
                    if (connected && port != null && driver?.device?.deviceId == device.deviceId) {
                        Log.d(TAG, "USB_OPEN_SKIPPED: same device already connected")
                        return@execute
                    }
                }

                closeInternal("reopening")
                setState(UsbState.CONNECTING)
                diagnosticLogger.log(
                    "USB",
                    "opening device id=${device.deviceId} vid=${device.vendorId} pid=${device.productId} generation=$generation"
                )

                val foundDriver = UsbSerialProber.getDefaultProber().findAllDrivers(usbManager)
                    .firstOrNull { it.device.deviceId == device.deviceId }
                    ?: throw IOException("No serial driver for USB device")
                driver = foundDriver
                diagnosticLogger.log("SERIAL", "driver=${foundDriver.javaClass.simpleName} ports=${foundDriver.ports.size}")

                val connection = usbManager.openDevice(device)
                    ?: throw IOException("Android could not open USB device")
                val serialPort = foundDriver.ports.firstOrNull()
                    ?: throw IOException("USB device has no serial port")
                val portIndex = foundDriver.ports.indexOf(serialPort)
                diagnosticLogger.log("SERIAL", "portIndex=$portIndex opening")

                serialPort.open(connection)
                serialPort.setParameters(
                    BAUD_RATE,
                    8,
                    UsbSerialPort.STOPBITS_1,
                    UsbSerialPort.PARITY_NONE
                )
                runCatching { serialPort.dtr = false }
                runCatching { serialPort.rts = false }
                diagnosticLogger.log(
                    "SERIAL",
                    "open=success config=115200/8/N/1 dtr=${runCatching { serialPort.dtr }.getOrNull()} rts=${runCatching { serialPort.rts }.getOrNull()}"
                )

                synchronized(this) {
                    if (generation != sessionGeneration) {
                        runCatching { serialPort.close() }
                        return@execute
                    }
                    port = serialPort
                    connected = true
                    ready = false
                    handshakePhase = HandshakePhase.WAITING_FOR_HOST_READY
                    selectedSlot = null
                    requestedSlot = null
                    receiveBuffer = StringBuilder()
                    lastError = null
                    setState(UsbState.HANDSHAKING)
                }

                Log.d(TAG, "USB_HANDSHAKING generation=$generation")
                diagnosticLogger.log(
                    "HANDSHAKE",
                    "serial port ready; waiting ${SERIAL_BOOT_SETTLE_MS}ms before HELLO generation=$generation"
                )

                startReader(serialPort, generation)
                heartbeatTask?.cancel(true)
                heartbeatTask = null

                handshakeRetryFuture?.cancel(true)
                handshakeRetryFuture = null
                timeSyncFuture?.cancel(true)
                timeSyncFuture = null

                helloFuture?.cancel(false)
                helloFuture = scheduler.schedule({
                    if (connected && generation == sessionGeneration && !ready &&
                        handshakePhase == HandshakePhase.WAITING_FOR_HOST_READY
                    ) {
                        diagnosticLogger.log("HANDSHAKE", "sending HELLO generation=$generation")
                        writeLine("HELLO", generation)
                        scheduleHandshakeTimeout(generation)
                    }
                }, SERIAL_BOOT_SETTLE_MS, TimeUnit.MILLISECONDS)
            } catch (t: Throwable) {
                if (generation != sessionGeneration) return@execute
                lastError = t.message ?: t.javaClass.simpleName
                diagnosticLogger.log("ERROR", "serial open failed: $lastError")
                Log.e(TAG, "USB_SERIAL_ERROR: open failed - ${t.message}")
                closeInternal("USB open failed: ${t.message}")
                setState(UsbState.ERROR)
            }
        }
    }

    private fun startReader(serialPort: UsbSerialPort, generation: Long) {
        readTask?.cancel(true)
        readTask = readExecutor.submit {
            val buffer = ByteArray(256)
            try {
                while (!Thread.currentThread().isInterrupted && connected && generation == sessionGeneration) {
                    val count = serialPort.read(buffer, READ_TIMEOUT_MS)
                    if (count <= 0) continue

                    val rawChunk = String(buffer, 0, count, StandardCharsets.UTF_8)
                    diagnosticLogger.log("RX_BYTES", rawChunk.replace("\n", "\\n"))

                    // USB serial streams occasionally expose NUL padding during startup.
                    // The SecureVault line protocol never uses NUL, so remove it before parsing.
                    receiveBuffer.append(rawChunk.replace("\u0000", ""))
                    processReceivedLines()
                }
            } catch (t: Throwable) {
                if (connected && generation == sessionGeneration) {
                    Log.e(TAG, "USB_SERIAL_ERROR: read failed - ${t.message}")
                    diagnosticLogger.log("ERROR", "serial read failed: ${t.message}")
                    close("USB link lost: ${t.message}")
                }
            }
        }
    }

    private fun processReceivedLines() {
        while (true) {
            val newline = receiveBuffer.indexOf("\n")
            if (newline < 0) return

            val rawLine = receiveBuffer
                .substring(0, newline)
                .replace("\u0000", "")
                .trim()
            receiveBuffer.delete(0, newline + 1)

            // Some CP210x/ESP32 USB-serial sessions emit a single startup byte (the
            // diagnostic log captured "?" before HELLO). Because the line reader buffers
            // until newline, that byte can be prefixed to the first real response, e.g.
            // "?USB_HOST_READY". Exact comparisons would silently discard the handshake.
            // Strip only a prefix before a recognized protocol marker; preserve ordinary
            // payload text and do not interpret arbitrary noise as a command response.
            val protocolMarkers = listOf(
                "USB_HOST_READY", "TIME_SYNCED", "SYNC_TIME_INVALID", "RATE_LIMITED",
                "USB_SESSION_EXPIRED", "USB_NOT_CONNECTED", "HEARTBEAT_OK", "LOCKED",
                "HSM_UNLOCK_FAILED", "TOTP_VALID", "TOTP_INVALID", "TOTP_INVALID_SLOT",
                "SLOT_SELECTED:", "SLOT_CREATED:", "SLOT_REMOVED:", "SLOT_ERROR:",
                "SLOTS:", "SLOT:", "SV2|"
            )
            val markerOffset = protocolMarkers
                .mapNotNull { marker -> rawLine.indexOf(marker).takeIf { it >= 0 } }
                .minOrNull()
            val line = if (markerOffset != null) rawLine.substring(markerOffset).trim() else rawLine

            if (line.isNotEmpty()) {
                lastProtocolEvent = line
                if (line != rawLine) {
                    diagnosticLogger.log("RX_NORMALIZED", "removed startup prefix from '$rawLine'")
                }
                diagnosticLogger.log("RX", line)
                handleLine(line)
            }
        }
    }

    private fun handleLine(line: String) {
        when {
            line == "USB_HOST_READY" -> {
                if (!connected) return
                ready = false
                handshakePhase = HandshakePhase.WAITING_FOR_TIME_SYNC
                selectedSlot = null
                requestedSlot = null
                handshakeTimeoutFuture?.cancel(false)
                helloFuture?.cancel(false)
                helloFuture = null
                setState(UsbState.HANDSHAKING)
                diagnosticLogger.log(
                    "HANDSHAKE",
                    "USB_HOST_READY received; waiting ${TIME_SYNC_DELAY_MS}ms before SYNC_TIME"
                )

                val generation = sessionGeneration
                timeSyncFuture?.cancel(false)
                timeSyncFuture = scheduler.schedule({
                    if (connected && generation == sessionGeneration &&
                        handshakePhase == HandshakePhase.WAITING_FOR_TIME_SYNC && !ready
                    ) {
                        diagnosticLogger.log("HANDSHAKE", "sending SYNC_TIME generation=$generation")
                        writeLine("SYNC_TIME:${System.currentTimeMillis() / 1000L}", generation)
                        scheduleReadyTimeout(generation)
                    }
                }, TIME_SYNC_DELAY_MS, TimeUnit.MILLISECONDS)
            }

            line == "TIME_SYNCED" -> {
                handshakeTimeoutFuture?.cancel(false)
                helloFuture?.cancel(false)
                helloFuture = null
                timeSyncFuture?.cancel(false)
                ready = true
                handshakePhase = HandshakePhase.READY
                selectedSlot = null
                requestedSlot = null
                lastError = null
                setState(UsbState.READY)
                Log.d(TAG, "USB_READY generation=$sessionGeneration")
                diagnosticLogger.log("HANDSHAKE", "TIME_SYNCED received; HSM READY")
                startHeartbeat(sessionGeneration)
                // This command is paced by the single write queue, so it cannot violate the
                // ESP32's 180 ms command-rate limiter immediately after SYNC_TIME.
                requestSlots()
            }

            line == "TOTP_VALID" -> notifyTotpResult(true, line)
            line == "TOTP_INVALID" -> notifyTotpResult(false, line)

            line.startsWith("SLOT_SELECTED:") -> {
                val slot = line.substringAfter(':').toIntOrNull()
                if (slot != null && slot in 1..slotCapacity && requestedSlot == slot) {
                    selectedSlot = slot
                    requestedSlot = null
                    notifyMessage(line)
                } else {
                    diagnosticLogger.log("SLOT", "ignored unexpected SLOT_SELECTED:$slot; requested=$requestedSlot")
                    notifyMessage("SLOT_SELECTION_MISMATCH")
                }
            }

            line.startsWith("SV2|VERSION|") -> firmwareVersion = line.substringAfterLast('|')
            line.startsWith("SV2|TRANSPORT|") -> transportInfo = line.substringAfterLast('|')
            line.startsWith("SV2|SECURITY|") -> securityInfo = line.substringAfterLast('|')
            line.startsWith("SV2|SLOTS|") -> {
                slotCapacity = line.substringAfterLast('|').toIntOrNull()?.coerceAtMost(8) ?: slotCapacity
            }

            line == "USB_SESSION_EXPIRED" -> restartHandshakeOnOpenPort(line)
            line == "USB_NOT_CONNECTED" -> {
                // A queued heartbeat from the just-expired session can arrive before the
                // recovery HELLO. Do not restart the reader/session a second time during recovery.
                if (handshakePhase == HandshakePhase.READY) restartHandshakeOnOpenPort(line)
                else notifyMessage(line)
            }

            line == "LOCKED" -> {
                // Firmware LOCK closes its logical host session. Re-establish it on the still-open
                // USB port so the Android UI cannot remain permanently stuck in READY=false/ready.
                notifyMessage(line)
                if (connected) restartHandshakeOnOpenPort(line)
            }

            line == "HSM_UNLOCK_FAILED" -> {
                lastError = "ESP32 HSM initialization failed"
                diagnosticLogger.log("ERROR", lastError ?: "HSM initialization failed")
                setState(UsbState.ERROR)
                close("HSM unlock failed")
            }

            line == "SYNC_TIME_INVALID" -> {
                lastError = "ESP32 rejected the Android time synchronization request"
                diagnosticLogger.log("ERROR", lastError ?: "SYNC_TIME_INVALID")
                setState(UsbState.ERROR)
                close("Time synchronization rejected by ESP32")
            }

            line == "RATE_LIMITED" -> handleRateLimited()

            line == "HEARTBEAT_OK" -> {
                // Heartbeat acknowledgement is intentionally not used to declare the HSM READY;
                // only TIME_SYNCED establishes READY.
                lastProtocolEvent = line
            }

            line.startsWith("SLOT_ERROR:") ||
                line.startsWith("TOTP_") ||
                line.startsWith("AUTH_") ||
                line.startsWith("SLOT_") ||
                line.startsWith("SLOTS:") ||
                line.startsWith("SV2|") -> notifyMessage(line)

            else -> notifyMessage(line)
        }
    }

    private fun handleRateLimited() {
        diagnosticLogger.log("HANDSHAKE", "firmware returned RATE_LIMITED phase=$handshakePhase")
        when (handshakePhase) {
            HandshakePhase.WAITING_FOR_HOST_READY -> {
                val generation = sessionGeneration
                handshakeRetryFuture?.cancel(false)
                handshakeRetryFuture = scheduler.schedule({
                    if (connected && generation == sessionGeneration && !ready) {
                        writeLine("HELLO", generation)
                        scheduleHandshakeTimeout(generation)
                    }
                }, HANDSHAKE_RETRY_DELAY_MS, TimeUnit.MILLISECONDS)
            }

            HandshakePhase.WAITING_FOR_TIME_SYNC -> {
                val generation = sessionGeneration
                timeSyncFuture?.cancel(false)
                timeSyncFuture = scheduler.schedule({
                    if (connected && generation == sessionGeneration && !ready) {
                        writeLine("SYNC_TIME:${System.currentTimeMillis() / 1000L}", generation)
                        scheduleReadyTimeout(generation)
                    }
                }, HANDSHAKE_RETRY_DELAY_MS, TimeUnit.MILLISECONDS)
            }

            HandshakePhase.READY,
            HandshakePhase.IDLE -> {
                // Normal commands are already paced at MIN_COMMAND_GAP_MS. Do not blindly retry
                // VERIFY_TOTP or provisioning here because duplicating a security-sensitive command
                // could produce a second authentication/provisioning attempt.
                notifyMessage("RATE_LIMITED")
            }
        }
    }

    private fun restartHandshakeOnOpenPort(reason: String) {
        // Keep sessionGeneration unchanged. It identifies the physical USB connection and is
        // also captured by the reader loop. Incrementing it here makes that reader exit, so
        // the recovery HELLO can be sent but its USB_HOST_READY/TIME_SYNCED responses are never
        // consumed. A new generation is reserved for detach/close/user reconnect only.
        val generation = synchronized(this) {
            if (!connected) return
            ready = false
            handshakePhase = HandshakePhase.WAITING_FOR_HOST_READY
            selectedSlot = null
            requestedSlot = null
            heartbeatTask?.cancel(true)
            heartbeatTask = null
            helloFuture?.cancel(false)
            helloFuture = null
            handshakeTimeoutFuture?.cancel(false)
            handshakeTimeoutFuture = null
            handshakeRetryFuture?.cancel(false)
            handshakeRetryFuture = null
            timeSyncFuture?.cancel(false)
            timeSyncFuture = null
            AppMonitorService.revokeAllSessions()
            setState(UsbState.HANDSHAKING)
            diagnosticLogger.log("HANDSHAKE", "$reason received; restarting HELLO on existing USB reader generation=$sessionGeneration")
            sessionGeneration
        }

        helloFuture = scheduler.schedule({
            if (connected && generation == sessionGeneration && !ready &&
                handshakePhase == HandshakePhase.WAITING_FOR_HOST_READY
            ) {
                writeLine("HELLO", generation)
                scheduleHandshakeTimeout(generation)
            }
        }, SESSION_RESTART_DELAY_MS, TimeUnit.MILLISECONDS)
    }

    private fun startHeartbeat(generation: Long) {
        heartbeatTask?.cancel(true)
        heartbeatTask = scheduler.scheduleAtFixedRate(
            {
                if (connected && ready && generation == sessionGeneration) {
                    writeLine("HEARTBEAT", generation)
                }
            },
            HEARTBEAT_INTERVAL_MS,
            HEARTBEAT_INTERVAL_MS,
            TimeUnit.MILLISECONDS
        )
    }

    private fun scheduleHandshakeTimeout(generation: Long) {
        handshakeTimeoutFuture?.cancel(false)
        handshakeTimeoutFuture = scheduler.schedule({
            if (connected && generation == sessionGeneration && !ready &&
                handshakePhase == HandshakePhase.WAITING_FOR_HOST_READY
            ) {
                lastError = "Handshake timeout: ESP32 did not return USB_HOST_READY"
                diagnosticLogger.log("HANDSHAKE", "timeout after ${HANDSHAKE_TIMEOUT_MS}ms; USB_HOST_READY not received")
                setState(UsbState.ERROR)
                close("Handshake timeout")
            }
        }, HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
    }

    private fun scheduleReadyTimeout(generation: Long) {
        handshakeTimeoutFuture?.cancel(false)
        handshakeTimeoutFuture = scheduler.schedule({
            if (connected && generation == sessionGeneration && !ready &&
                handshakePhase == HandshakePhase.WAITING_FOR_TIME_SYNC
            ) {
                lastError = "Time synchronization timeout: ESP32 did not return TIME_SYNCED"
                diagnosticLogger.log("HANDSHAKE", "timeout after ${HANDSHAKE_TIMEOUT_MS}ms; TIME_SYNCED not received")
                setState(UsbState.ERROR)
                close("Time synchronization timeout")
            }
        }, HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
    }

    /**
     * All writes pass through one executor. This both preserves command ordering and enforces the
     * firmware's 180 ms command gap for commands such as TIME_SYNC -> GET_SLOTS -> SELECT_SLOT.
     */
    private fun writeLine(line: String, generation: Long) {
        writeExecutor.execute {
            if (!connected || generation != sessionGeneration) return@execute

            val serialPort = port ?: return@execute
            try {
                val now = System.currentTimeMillis()
                val waitMs = MIN_COMMAND_GAP_MS - (now - lastCommandWriteAtMs)
                if (lastCommandWriteAtMs != 0L && waitMs > 0L) {
                    Thread.sleep(waitMs)
                }

                if (!connected || generation != sessionGeneration || serialPort !== port) return@execute

                val logged = if (line.startsWith("VERIFY_TOTP:")) {
                    line.substringBeforeLast(':') + ":[REDACTED]"
                } else {
                    line
                }
                diagnosticLogger.log("TX", logged)
                serialPort.write((line + "\n").toByteArray(StandardCharsets.UTF_8), 1000)
                lastCommandWriteAtMs = System.currentTimeMillis()
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
            } catch (t: Throwable) {
                if (connected && generation == sessionGeneration) {
                    lastError = t.message ?: t.javaClass.simpleName
                    Log.e(TAG, "USB_SERIAL_ERROR: write failed - ${t.message}")
                    diagnosticLogger.log("ERROR", "serial write failed: ${t.message}")
                    close("USB write failed: ${t.message}")
                }
            }
        }
    }

    fun close(reason: String = "closed") {
        ioExecutor.execute {
            synchronized(this) {
                sessionGeneration += 1L
                clearPermissionTransactionInternal()
                closeInternal(reason)
            }
            setState(UsbState.DISCONNECTED)
            Log.d(TAG, "USB_DISCONNECTED: $reason")
        }
    }

    /** Does not change sessionGeneration; callers decide whether the session itself is invalidated. */
    private fun closeInternal(reason: String) {
        Log.d(TAG, "USB_CLOSING: $reason")
        connected = false
        ready = false
        handshakePhase = HandshakePhase.IDLE
        selectedSlot = null
        requestedSlot = null
        heartbeatTask?.cancel(true)
        heartbeatTask = null
        handshakeTimeoutFuture?.cancel(true)
        handshakeTimeoutFuture = null
        helloFuture?.cancel(true)
        helloFuture = null
        handshakeRetryFuture?.cancel(true)
        handshakeRetryFuture = null
        timeSyncFuture?.cancel(true)
        timeSyncFuture = null
        permissionTimeoutFuture?.cancel(true)
        permissionTimeoutFuture = null
        readTask?.cancel(true)
        readTask = null
        try { port?.close() } catch (_: Throwable) {}
        receiveBuffer = StringBuilder()
        driver = null
        port = null
        AppMonitorService.revokeAllSessions()
    }

    private fun setState(newState: UsbState) {
        synchronized(this) {
            currentState = newState
        }
        notifyCurrentStateToListeners()
    }

    private fun notifyCurrentStateToListeners() {
        val isConn = connected
        val isReady = ready
        val state = currentState
        synchronized(listeners) {
            listeners.toList().forEach { listener ->
                try {
                    listener.onUsbStateChanged(isConn)
                    listener.onHardwareReady(isReady)
                    listener.onUsbStateUpdated(state)
                } catch (t: Throwable) {
                    Log.e(TAG, "Error notifying listener: ${t.message}")
                }
            }
        }
    }

    private fun notifyTotpResult(valid: Boolean, message: String) {
        synchronized(listeners) {
            listeners.toList().forEach { listener ->
                try { listener.onTotpResult(valid, message) } catch (_: Throwable) {}
            }
        }
    }

    private fun notifyMessage(message: String) {
        synchronized(listeners) {
            listeners.toList().forEach { listener ->
                try { listener.onHardwareMessage(message) } catch (_: Throwable) {}
            }
        }
    }
}
