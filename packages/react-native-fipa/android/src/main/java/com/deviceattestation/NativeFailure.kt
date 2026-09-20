package com.deviceattestation

/** Stable codes only. Never retain underlying exceptions, tokens or native diagnostics. */
internal class NativeFailure(val code: String) : Exception(code)

internal fun requireNative(condition: Boolean, code: String = "key_invalid_input") {
    if (!condition) throw NativeFailure(code)
}
