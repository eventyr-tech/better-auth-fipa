package com.deviceattestation

import java.util.Locale

/** Receives a parsed hostname, never an authority or an unparsed URL. */
internal object FirstPartyLocalOrigin {
    fun contains(hostname: String): Boolean {
        val host = hostname.lowercase(Locale.ROOT)
        if (host in setOf("127.0.0.1", "::1", "[::1]")) return true
        val name = host.removeSuffix(".")
        if (name.length > 253) return false
        val labels = name.split('.')
        return labels.last() == "localhost" &&
            labels.all { it.matches(Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) }
    }
}
