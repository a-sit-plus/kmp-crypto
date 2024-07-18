package at.asitplus.cryptotest

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.provider.os.IOSKeychainProvider
import at.asitplus.crypto.provider.os.TPMSigningProvider
import io.github.aakira.napier.Napier
import io.ktor.util.encodeBase64
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

internal actual fun getSystemKeyStore(): TPMSigningProvider = IOSKeychainProvider

/*@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun generateKey(
    alg: CryptoAlgorithm,
    attestation: ByteArray?,
    withBiometricAuth: Duration?
): KmmResult<TbaKey> {

    val specificCryptoOps = withBiometricAuth?.let {
        IosSpecificCryptoOps.withSecAccessControlFlagsAndReuse(
            kSecAccessControlTouchIDCurrentSet, withBiometricAuth
        )
    } ?: IosSpecificCryptoOps.plain()



    val hasKey = CryptoProvider.hasKey(ALIAS, specificCryptoOps)
    Napier.w { "Key with alias $ALIAS exists: $hasKey" }

    if (hasKey.getOrThrow()) {
        Napier.w { "trying to clear key" }
        println(CryptoProvider.deleteEntry(ALIAS, specificCryptoOps))
    }

    Napier.w { "creating signing key" }


    return (if (attestation == null) {
        CryptoProvider.createSigningKey(
            ALIAS,
            alg,
            specificCryptoOps
        ).map { it to listOf() }
    } else CryptoProvider.createTbaP256Key(
        ALIAS,
        attestation,
        specificCryptoOps
    ))
}

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun sign(
    data: ByteArray,
    alg: CryptoAlgorithm,
    signingKey: CryptoPrivateKey
): KmmResult<CryptoSignature> {
    if (signingKey !is IosPrivateKey) throw IllegalArgumentException("Not an iOS Private Key!")
    return CryptoProvider.sign(data, signingKey, alg)
}

internal actual suspend fun loadPubKey() = CryptoProvider.getPublicKey(ALIAS)

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun loadPrivateKey(): KmmResult<CryptoKeyPair> =
    CryptoProvider.getKeyPair(ALIAS, IosSpecificCryptoOps())

internal actual suspend fun storeCertChain(): KmmResult<Unit> =
    CryptoProvider.storeCertificateChain(
        ALIAS + "CRT_CHAIN",
        SAMPLE_CERT_CHAIN
    )

internal actual suspend fun getCertChain(): KmmResult<List<X509Certificate>> =
    CryptoProvider.getCertificateChain(
        ALIAS + "CRT_CHAIN"
    )*/