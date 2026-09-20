package com.deviceattestation

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityException
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import com.google.android.play.core.integrity.model.StandardIntegrityErrorCode
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor
import java.util.concurrent.Executors

internal object AndroidPlayIntegrity {
    private var shared: StandardIntegrityCoordinator? = null

    @Synchronized
    fun coordinator(context: Context): StandardIntegrityCoordinator {
        shared?.let {
            return it
        }
        val manager = IntegrityManagerFactory.createStandard(context.applicationContext)
        val direct = Executor { it.run() }
        val factory = StandardTokenFactory { project ->
            val prepared = CompletableFuture<StandardTokenProvider>()
            manager
                .prepareIntegrityToken(
                    PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(project).build()
                )
                .addOnSuccessListener(direct) { provider ->
                    prepared.complete(
                        StandardTokenProvider { hash ->
                            val token = CompletableFuture<String>()
                            provider
                                .request(
                                    StandardIntegrityTokenRequest.builder()
                                        .setRequestHash(hash)
                                        .build()
                                )
                                .addOnSuccessListener(direct) { result ->
                                    token.complete(result.token())
                                }
                                .addOnFailureListener(direct) { error ->
                                    val invalid =
                                        error is StandardIntegrityException &&
                                            error.errorCode ==
                                                StandardIntegrityErrorCode
                                                    .INTEGRITY_TOKEN_PROVIDER_INVALID
                                    token.completeExceptionally(
                                        NativeFailure(
                                            if (invalid) "integrity_provider_invalid"
                                            else "integrity_unavailable"
                                        )
                                    )
                                }
                            token
                        }
                    )
                }
                .addOnFailureListener(direct) {
                    prepared.completeExceptionally(NativeFailure("integrity_unavailable"))
                }
            prepared
        }
        val timer =
            Executors.newSingleThreadScheduledExecutor { task ->
                Thread(task, "DeviceAttestationIntegrityDeadline").apply { isDaemon = true }
            }
        return StandardIntegrityCoordinator(factory, timer).also { shared = it }
    }
}
