package com.deviceattestation

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContract
import androidx.activity.result.contract.ActivityResultContracts
import androidx.browser.auth.AuthTabIntent
import androidx.browser.customtabs.CustomTabsClient
import androidx.core.app.ActivityOptionsCompat

/**
 * Private, result-only activity. No deep-link receiver or exported callback. Platform request codes
 * let cancellation finish our exact child Auth Tab, without bringing an arbitrary activity or
 * callback URL into the task.
 */
@Suppress("DEPRECATION")
class FirstPartyBrowserActivity : Activity() {
    private var ticket: String? = null
    private val dismiss: () -> Unit = {
        try {
            finishActivity(AUTH_REQUEST)
        } finally {
            finish()
        }
    }
    private val launcher =
        object : ActivityResultLauncher<Intent>() {
            override fun launch(input: Intent, options: ActivityOptionsCompat?) {
                startActivityForResult(input, AUTH_REQUEST, options?.toBundle())
            }

            override fun unregister() {}

            override val contract: ActivityResultContract<Intent, *> =
                ActivityResultContracts.StartActivityForResult()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val current = intent?.getStringExtra(TICKET)
        if (current == null || !current.matches(Regex("[A-Za-z0-9_-]{43}"))) {
            finish()
            return
        }
        ticket = current
        val attachment = AndroidFirstPartyBrowser.coordinator.attach(current, dismiss)
        if (attachment == null) {
            dismiss()
            return
        }
        // Configuration recreation retains the platform's pending activity result.
        // Process death has no coordinator entry and may never reopen the handoff.
        if (!attachment.shouldLaunch) return
        try {
            val provider = CustomTabsClient.getPackageName(this, emptyList())
            if (provider == null || !CustomTabsClient.isAuthTabSupported(this, provider)) {
                AndroidFirstPartyBrowser.coordinator.unavailable(current)
                return
            }
            val builder = AuthTabIntent.Builder()
            if (Build.VERSION.SDK_INT >= 29) builder.setEphemeralBrowsingEnabled(true)
            val auth = builder.build()
            // Prevent the checked provider from being replaced by another VIEW handler.
            auth.intent.setPackage(provider)
            val request = attachment.request
            val callback = Uri.parse(request.redirectUri)
            if (callback.scheme.equals("https", ignoreCase = true)) {
                auth.launch(
                    launcher,
                    Uri.parse(request.url),
                    callback.host!!,
                    callback.path.orEmpty(),
                )
            } else {
                auth.launch(launcher, Uri.parse(request.url), callback.scheme!!)
            }
        } catch (_: Exception) {
            AndroidFirstPartyBrowser.coordinator.unavailable(current)
        }
    }

    override fun onResume() {
        super.onResume()
        // Includes elapsed time while the device was asleep or UI dispatch paused.
        if (ticket?.let { AndroidFirstPartyBrowser.coordinator.isActive(it) } != true) dismiss()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != AUTH_REQUEST) return
        ticket?.let {
            // Never log, persist, forward via Linking, or expose this URI to the app.
            AndroidFirstPartyBrowser.coordinator.result(it, resultCode, data?.dataString)
        }
        finish()
    }

    override fun onDestroy() {
        ticket?.let {
            AndroidFirstPartyBrowser.coordinator.detached(it, dismiss, isChangingConfigurations)
        }
        super.onDestroy()
    }

    companion object {
        internal const val TICKET = "com.deviceattestation.BROWSER_TICKET"
        internal const val AUTH_REQUEST = 8417
    }
}
