package com.deviceattestation

import com.facebook.react.bridge.Promise
import java.lang.reflect.Proxy
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class BridgeOperationsTest {
    private class Completion {
        val calls = CopyOnWriteArrayList<Pair<String, List<Any?>>>()
        val completed = CountDownLatch(1)
        val promise =
            Proxy.newProxyInstance(Promise::class.java.classLoader, arrayOf(Promise::class.java)) {
                proxy,
                method,
                args ->
                when (method.name) {
                    "hashCode" -> System.identityHashCode(proxy)
                    "equals" -> proxy === args?.get(0)
                    "toString" -> "TestPromise"
                    else -> {
                        calls.add(method.name to (args?.toList() ?: emptyList()))
                        completed.countDown()
                        null
                    }
                }
            } as Promise
    }

    private fun operations() = BridgeOperations(1, 1, { "unavailable" }, "Safe message")

    @Test
    fun invalidationRejectsPendingAndNewWorkAndIgnoresLateCallbacks() {
        val operations = operations()
        val pending = Completion()
        assertTrue(operations.begin(pending.promise))
        operations.invalidate()
        operations.resolve(pending.promise, "late result")
        operations.reject(pending.promise, IllegalStateException("private detail"))
        assertEquals(listOf("reject" to listOf("unavailable", "Safe message")), pending.calls)
        val after = Completion()
        operations.execute(after.promise) { fail("Work after invalidation must not run") }
        assertEquals(pending.calls, after.calls)
    }

    @Test
    fun completionAndCleanupFailureStillSettleOnlyOnce() {
        val operations = operations()
        val completed = Completion()
        val pending = Completion()
        operations.begin(completed.promise)
        operations.resolve(completed.promise, "result")
        operations.begin(pending.promise)
        try {
            operations.invalidate { throw IllegalStateException("cleanup failed") }
            fail("Expected cleanup failure")
        } catch (_: IllegalStateException) {}
        operations.invalidate()
        assertEquals(listOf("resolve" to listOf("result")), completed.calls)
        assertEquals(listOf("reject" to listOf("unavailable", "Safe message")), pending.calls)
    }

    @Test
    fun queueIsBoundedAndExceptionsAreSanitized() {
        val operations = operations()
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val active = Completion()
        val queued = Completion()
        val overflow = Completion()
        try {
            operations.execute(active.promise) {
                started.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                "success"
            }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            operations.execute(queued.promise) { throw IllegalStateException("secret") }
            operations.execute(overflow.promise) { fail("Queue overflow must not run") }
            assertTrue(overflow.completed.await(5, TimeUnit.SECONDS))
            assertEquals(listOf("reject" to listOf("unavailable", "Safe message")), overflow.calls)
            release.countDown()
            assertTrue(active.completed.await(5, TimeUnit.SECONDS))
            assertTrue(queued.completed.await(5, TimeUnit.SECONDS))
            assertEquals(listOf("resolve" to listOf("success")), active.calls)
            assertEquals(overflow.calls, queued.calls)
        } finally {
            release.countDown()
            operations.invalidate()
        }
    }
}
