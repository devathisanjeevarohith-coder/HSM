package com.android.securevaultlocker.locker.service

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class SecureVaultDiagnosticLogger(context: Context) {
    private val appContext = context.applicationContext
    private val logFile = File(appContext.filesDir, "securevault_usb_diagnostic.log")
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    @Synchronized
    fun log(category: String, message: String) {
        val timestamp = dateFormat.format(Date())
        val logLine = "[$timestamp] [$category] $message\n"
        try {
            logFile.appendText(logLine)
        } catch (_: Throwable) {}
    }

    @Synchronized
    fun getLogContent(): String {
        return try {
            if (logFile.exists()) logFile.readText() else "No diagnostic logs found."
        } catch (t: Throwable) {
            "Error reading log: ${t.message}"
        }
    }

    @Synchronized
    fun clearLogs() {
        try {
            if (logFile.exists()) logFile.delete()
        } catch (_: Throwable) {}
    }

    fun getShareIntent(context: Context): Intent? {
        return try {
            if (!logFile.exists()) return null
            val uri: Uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                logFile
            )
            Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "SecureVault USB Diagnostic Log")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
        } catch (t: Throwable) {
            null
        }
    }
}
