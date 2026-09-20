package com.deviceattestation

import android.app.Activity
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.common.LifecycleState

/**
 * All activity operations run on the main thread. Only an opaque, in-memory presentation ticket
 * crosses the helper-activity boundary.
 */
internal object AndroidFirstPartyBrowser {
    private val main = Handler(Looper.getMainLooper())
    val coordinator =
        FirstPartyBrowserCoordinator(
            now = SystemClock::elapsedRealtimeNanos,
            schedule = { delay, action ->
                val work = Runnable(action)
                main.postDelayed(work, delay)
                ({ main.removeCallbacks(work) })
            },
        )

    fun open(
        owner: Any,
        context: ReactApplicationContext,
        request: BrowserRequest,
        isInvalidated: () -> Boolean,
        complete: (String?, Throwable?) -> Unit,
    ) {
        main.post {
            if (isInvalidated()) {
                complete(null, NativeFailure("browser_cancelled"))
                return@post
            }
            val activity = context.currentActivity
            if (
                context.lifecycleState != LifecycleState.RESUMED ||
                    activity == null ||
                    activity.isFinishing ||
                    activity.isDestroyed
            ) {
                complete(null, NativeFailure("browser_unavailable"))
                return@post
            }
            coordinator
                .open(owner, request) { ticket -> present(activity, ticket) }
                .whenComplete(complete)
        }
    }

    private fun present(activity: Activity, ticket: String) {
        activity.startActivity(
            Intent(activity, FirstPartyBrowserActivity::class.java)
                .putExtra(FirstPartyBrowserActivity.TICKET, ticket)
        )
    }

    fun cancel(owner: Any, id: String, complete: () -> Unit) {
        main.post {
            coordinator.cancel(owner, id)
            complete()
        }
    }

    fun invalidate(owner: Any) {
        main.post { coordinator.invalidate(owner) }
    }
}
