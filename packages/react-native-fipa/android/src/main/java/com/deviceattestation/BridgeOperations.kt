package com.deviceattestation

import com.facebook.react.bridge.Promise
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Per-module bounded work and exactly-once promise completion. No exception details cross JS. */
internal class BridgeOperations(
    threads: Int,
    capacity: Int,
    private val errorCode: (Throwable?) -> String,
    private val message: String,
    private val unavailable: Throwable? = null,
) {
    private val workers =
        ThreadPoolExecutor(
            threads,
            threads,
            0L,
            TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(capacity),
        )
    private val pending = ConcurrentHashMap<Promise, Boolean>()
    @Volatile
    var invalidated = false
        private set

    fun begin(promise: Promise): Boolean {
        pending[promise] = true
        if (invalidated) {
            reject(promise, unavailable)
            return false
        }
        return true
    }

    fun reject(promise: Promise, error: Throwable?) {
        if (pending.remove(promise) != null) promise.reject(errorCode(error), message)
    }

    fun resolve(promise: Promise, value: Any?) {
        if (pending.remove(promise) != null) promise.resolve(value)
    }

    fun execute(promise: Promise, operation: () -> Any?) {
        if (!begin(promise)) return
        try {
            workers.execute {
                try {
                    resolve(promise, operation())
                } catch (error: Exception) {
                    reject(promise, error)
                }
            }
        } catch (error: Exception) {
            reject(promise, error)
        }
    }

    fun invalidate(cleanup: () -> Unit = {}) {
        invalidated = true
        try {
            cleanup()
        } finally {
            workers.shutdownNow()
            pending.keys.forEach { reject(it, unavailable) }
        }
    }
}
