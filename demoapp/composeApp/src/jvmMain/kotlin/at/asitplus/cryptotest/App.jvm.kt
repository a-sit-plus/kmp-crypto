package at.asitplus.cryptotest

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.provider.CryptoPrivateKey
import at.asitplus.crypto.provider.JvmSpecifics
import at.asitplus.crypto.provider.CryptoProvider
import at.asitplus.crypto.provider.TbaKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyStore
import kotlin.time.Duration

val PROVIDER = BouncyCastleProvider()
val JVM_OPTS =
    JvmSpecifics(
        PROVIDER,
        KeyStore.getInstance("PKCS12", PROVIDER).apply { load(null, null) },
        privateKeyPassword = null
    )

internal actual suspend fun generateKey(
    alg: CryptoAlgorithm,
    attestation: ByteArray?,
    withBiometricAuth: Duration?,

    ): KmmResult<TbaKey> = CryptoProvider.createSigningKey(ALIAS, alg, JVM_OPTS).map { it to listOf() }

internal actual suspend fun sign(
    data: ByteArray,
    alg: CryptoAlgorithm,
    signingKey: CryptoPrivateKey
): KmmResult<CryptoSignature> = CryptoProvider.sign(data, signingKey, alg)

internal actual suspend fun loadPubKey() = CryptoProvider.getPublicKey(ALIAS, JVM_OPTS)
internal actual suspend fun loadPrivateKey() = CryptoProvider.getKeyPair(ALIAS, JVM_OPTS)

internal actual suspend fun storeCertChain(): KmmResult<Unit> =
    CryptoProvider.storeCertificateChain(ALIAS + "CRT_CHAIN", SAMPLE_CERT_CHAIN, JVM_OPTS)

internal actual suspend fun getCertChain(): KmmResult<List<X509Certificate>> =
    CryptoProvider.getCertificateChain(
        ALIAS + "CRT_CHAIN", JVM_OPTS
    )