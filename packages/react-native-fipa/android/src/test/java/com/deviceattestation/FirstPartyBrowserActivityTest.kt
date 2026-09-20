package com.deviceattestation

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.ResolveInfo
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.Looper
import androidx.browser.auth.AuthTabIntent
import androidx.browser.customtabs.CustomTabsIntent
import androidx.browser.customtabs.CustomTabsService
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.annotation.LooperMode
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowActivity

@Implements(Activity::class)
class BrowserActivityShadow : ShadowActivity() {
    val finishedRequests = mutableListOf<Int>()

    @Implementation
    fun finishActivity(requestCode: Int) {
        finishedRequests.add(requestCode)
    }
}

/**
 * Framework/manifest/result wiring under emulation. No claim about a real browser, Digital Asset
 * Links, Android Keystore or physical devices.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28, 35], shadows = [BrowserActivityShadow::class])
@LooperMode(LooperMode.Mode.PAUSED)
class FirstPartyBrowserActivityTest {
    private val app
        get() = RuntimeEnvironment.getApplication()

    private val owner = Any()
    private val coordinator
        get() = AndroidFirstPartyBrowser.coordinator

    private var current = ""
    private val controllers = mutableListOf<ActivityController<FirstPartyBrowserActivity>>()
    private var requestId = ""
    private val provider = "com.example.browser"

    private fun browser(supported: Boolean = true) {
        val pm = shadowOf(app.packageManager)
        val application = ApplicationInfo().apply { packageName = provider }
        val activity =
            ResolveInfo().apply {
                activityInfo =
                    ActivityInfo().apply {
                        packageName = provider
                        name = "$provider.Browser"
                        applicationInfo = application
                    }
            }
        pm.addResolveInfoForIntent(Intent(Intent.ACTION_VIEW, Uri.parse("http://")), activity)
        val service =
            ResolveInfo().apply {
                serviceInfo =
                    ServiceInfo().apply {
                        packageName = provider
                        name = "$provider.Service"
                        applicationInfo = application
                    }
                filter =
                    IntentFilter(CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION).apply {
                        if (supported) addCategory(CustomTabsService.CATEGORY_AUTH_TAB)
                    }
            }
        pm.addResolveInfoForIntent(
            Intent(CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION).setPackage(provider),
            service,
        )
        pm.addResolveInfoForIntent(Intent(CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION), service)
    }

    private fun begin(redirect: String = "com.example:/oauth/callback"): CompletableFuture<String> {
        requestId = FirstPartyCrypto.randomToken()
        return coordinator.open(
            owner,
            BrowserRequest(
                requestId,
                "https://auth.example/authorize?request_uri=one-use-secret",
                redirect,
                300000.0,
                false,
            ),
        ) {
            current = it
        }
    }

    private fun activity(ticket: String = current): ActivityController<FirstPartyBrowserActivity> =
        Robolectric.buildActivity(
                FirstPartyBrowserActivity::class.java,
                Intent(app, FirstPartyBrowserActivity::class.java)
                    .putExtra(FirstPartyBrowserActivity.TICKET, ticket),
            )
            .also { controllers.add(it) }
            .create()
            .start()
            .resume()
            .visible()

    private fun rejected(code: String, output: CompletableFuture<String>) {
        assertTrue(output.isDone)
        try {
            output.get()
            fail("Expected rejection")
        } catch (error: ExecutionException) {
            assertEquals(code, (error.cause as NativeFailure).code)
        }
    }

    @After
    fun cleanup() {
        coordinator.invalidate(owner)
        controllers.forEach { it.pause().stop().destroy() }
        shadowOf(Looper.getMainLooper()).idle()
    }

    @Test
    fun activityIsPrivateAndItsIntentContainsOnlyAnOpaqueTicket() {
        val info =
            app.packageManager.getActivityInfo(
                ComponentName(app, FirstPartyBrowserActivity::class.java),
                0,
            )
        assertFalse(info.exported)
        browser()
        begin()
        val instance = activity().get()
        assertEquals(setOf(FirstPartyBrowserActivity.TICKET), instance.intent.extras!!.keySet())
        assertNull(instance.intent.data)
        val started = shadowOf(instance).nextStartedActivityForResult
        assertEquals(provider, started.intent.`package`)
        assertEquals(FirstPartyBrowserActivity.AUTH_REQUEST, started.requestCode)
        assertTrue(started.intent.getBooleanExtra(AuthTabIntent.EXTRA_LAUNCH_AUTH_TAB, false))
        assertEquals(
            "com.example",
            started.intent.getStringExtra(AuthTabIntent.EXTRA_REDIRECT_SCHEME),
        )
        assertEquals(
            Build.VERSION.SDK_INT >= 29,
            started.intent.getBooleanExtra(CustomTabsIntent.EXTRA_ENABLE_EPHEMERAL_BROWSING, false),
        )
    }

    @Test
    fun activityResultReturnsToOwnedPromiseWithoutDeepLinkDispatch() {
        browser()
        val output = begin()
        val instance = activity().get()
        val child = shadowOf(instance).nextStartedActivityForResult
        // Robolectric maintains separate queues for ordinary starts and starts
        // for result. Consume the original Auth Tab launch from both queues.
        assertEquals(child.intent, shadowOf(instance).nextStartedActivity)
        val callback =
            "com.example:/oauth/callback?code=opaque&state=bound&iss=https%3A%2F%2Fauth.example"
        shadowOf(instance)
            .receiveResult(child.intent, Activity.RESULT_OK, Intent().setData(Uri.parse(callback)))
        assertEquals(callback, output.get())
        assertTrue(instance.isFinishing)
        assertNull(shadowOf(instance).nextStartedActivity)
    }

    @Test
    fun httpsUsesVerifiedHostAndPathAndFailureCannotSucceed() {
        browser()
        val output = begin("https://callback.example/auth/complete")
        val instance = activity().get()
        val child = shadowOf(instance).nextStartedActivityForResult
        assertEquals(
            "callback.example",
            child.intent.getStringExtra(AuthTabIntent.EXTRA_HTTPS_REDIRECT_HOST),
        )
        assertEquals(
            "/auth/complete",
            child.intent.getStringExtra(AuthTabIntent.EXTRA_HTTPS_REDIRECT_PATH),
        )
        shadowOf(instance)
            .receiveResult(
                child.intent,
                AuthTabIntent.RESULT_VERIFICATION_FAILED,
                Intent().setData(Uri.parse("https://callback.example/auth/complete?code=secret")),
            )
        rejected("browser_failed", output)
        assertTrue(instance.isFinishing)
    }

    @Test
    fun cancellationFinishesTheExactChildAndIgnoresLateResult() {
        browser()
        val output = begin()
        val instance = activity().get()
        val child = shadowOf(instance).nextStartedActivityForResult
        coordinator.cancel(owner, requestId)
        rejected("browser_cancelled", output)
        assertTrue(instance.isFinishing)
        assertEquals(
            FirstPartyBrowserActivity.AUTH_REQUEST,
            Shadow.extract<BrowserActivityShadow>(instance).finishedRequests.single(),
        )
        shadowOf(instance)
            .receiveResult(
                child.intent,
                Activity.RESULT_OK,
                Intent().setData(Uri.parse("com.example:/oauth/callback?code=secret")),
            )
        rejected("browser_cancelled", output)
    }

    @Test
    fun unsupportedBrowserNeverFallsBackToGeneralCustomTabs() {
        browser(false)
        val output = begin()
        val instance = activity().get()
        rejected("browser_unavailable", output)
        assertTrue(instance.isFinishing)
        assertNull(shadowOf(instance).nextStartedActivity)
    }

    @Test
    fun unknownTicketAfterProcessLossCannotLaunchOrAcceptAnything() {
        browser()
        val instance = activity(FirstPartyCrypto.randomToken()).get()
        assertTrue(instance.isFinishing)
        assertNull(shadowOf(instance).nextStartedActivity)
    }

    @Test
    fun recreatedActivityDoesNotLaunchTheOneUseURLAgain() {
        browser()
        val output = begin()
        val controller = activity()
        assertNotNull(shadowOf(controller.get()).nextStartedActivity)
        controller.recreate()
        assertFalse(output.isDone)
        assertNull(shadowOf(controller.get()).nextStartedActivity)
        coordinator.cancel(owner, requestId)
        rejected("browser_cancelled", output)
        assertTrue(controller.get().isFinishing)
    }
}
