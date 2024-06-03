package at.asitplus.crypto.provider

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.failure
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.*
import at.asitplus.crypto.datatypes.asn1.Asn1Exception
import at.asitplus.crypto.datatypes.asn1.Asn1String
import at.asitplus.crypto.datatypes.asn1.Asn1Time
import at.asitplus.crypto.datatypes.pki.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import java.io.ByteArrayInputStream
import java.security.*
import java.security.InvalidParameterException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.spec.ECGenParameterSpec
import kotlin.random.Random
import kotlin.time.Duration.Companion.days


val crtFactMut = Mutex()
val certificateFactory = CertificateFactory.getInstance("X.509")

class JvmSpecifics(
    val provider: Provider,
    val keyStore: KeyStore,
    val privateKeyPassword: CharArray?
) : PlatformCryptoOpts

class JvmPrivateKey(val delegate: PrivateKey, platformSpecifics: JvmSpecifics) :
    CryptoPrivateKey(Platform.Jvm, platformSpecifics)

internal actual suspend fun clearKey(
    alias: String,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<Unit> {
    if (platformSpecifics !is JvmSpecifics) {
        throw InvalidParameterException("JvmSpecifics required!")
    }
    return runCatching {
        if (platformSpecifics.keyStore.containsAlias(alias))
            platformSpecifics.keyStore.deleteEntry(alias)
    }.wrap()
}

internal actual suspend fun keyExists(
    alias: String,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<Boolean> {
    if (platformSpecifics !is JvmSpecifics) {
        throw InvalidParameterException("JvmSpecifics required!")
    }
    return runCatching { platformSpecifics.keyStore.containsAlias(alias) }.wrap()
}

internal actual suspend fun createKey(
    alias: String,
    cryptoAlgorithm: CryptoAlgorithm,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<CryptoKeyPair> {
    if (platformSpecifics !is JvmSpecifics) {
        throw InvalidParameterException("JvmSpecifics required!")
    }
    if (!cryptoAlgorithm.isEc) throw UnsupportedAlgorithmException(cryptoAlgorithm, "Only EC is supported")


    return runCatching {
        KeyPairGenerator.getInstance("EC", platformSpecifics.provider).let {
            it.initialize(cryptoAlgorithm.name.substring(2).toInt())
            it.genKeyPair()
        }
    }.mapCatching {

        val fromJcaPublicKey = CryptoPublicKey.fromJcaPublicKey(it.public)
        val tbs = TbsCertificate(
            serialNumber = Random.nextBytes(32),
            signatureAlgorithm = cryptoAlgorithm,
            issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(alias)))),
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(alias)))),
            validFrom = Asn1Time(Clock.System.now()),
            validUntil = Asn1Time(Clock.System.now() + 1.days),
            publicKey = fromJcaPublicKey.getOrThrow()
        )
        val jvmPrivateKey = JvmPrivateKey(it.private, platformSpecifics)
        val certSig = signData(tbs.encodeToDer(), jvmPrivateKey, cryptoAlgorithm)
        val cert = X509Certificate(tbs, cryptoAlgorithm, certSig.getOrThrow())
        platformSpecifics.keyStore.setKeyEntry(
            alias,
            it.private,
            platformSpecifics.privateKeyPassword,
            crtFactMut.withLock {
                arrayOf(certificateFactory.let { it.generateCertificate(ByteArrayInputStream(cert.encodeToDer())) })
            }
        )

        jvmPrivateKey to fromJcaPublicKey
            .getOrThrow() as CryptoPublicKey.EC
    }.wrap().mapFailure {
        if (it is CertificateException || it is Asn1Exception) EncodingException(
            it.message,
            it
        ) else CryptoExecutionException(it.message, it)
    } /*this cast is not really necessary, but the compiler gets confused by mapCatching*/ as KmmResult<CryptoKeyPair>
}

internal actual suspend fun signData(
    data: ByteArray,
    signingKey: CryptoPrivateKey,
    algorithm: CryptoAlgorithm
): KmmResult<CryptoSignature> {
    if (signingKey !is JvmPrivateKey) {
        throw InvalidParameterException(signingKey.platformSpecifics, "Not a JVM Key")
    }
    return runCatching {
        Signature.getInstance(algorithm.jcaName, (signingKey.platformSpecifics as JvmSpecifics).provider).let {
            it.initSign(signingKey.delegate)
            it.update(data)
            CryptoSignature.parseFromJca(it.sign(), algorithm)
        }
    }.wrap()
}

internal actual suspend fun createAttestedP256Key(
    alias: String,
    attestationChallenge: ByteArray,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<TbaKey> {
    return failure(UnsupportedAlgorithmException(CryptoAlgorithm.ES256, msg = "Jvm does not support attestation"))
}


internal actual suspend fun doVerify(
    algorithm: CryptoAlgorithm,
    publicKey: CryptoPublicKey.EC,
    data: ByteArray,
    detachedSignature: CryptoSignature
): KmmResult<Boolean> =
    runCatching {
        Signature.getInstance(algorithm.jcaName).let {
            it.initVerify(publicKey.getJcaPublicKey().getOrThrow())
            it.update(data)
            it.verify(detachedSignature.jcaSignatureBytes)
        }
    }.wrap()

internal actual suspend fun doGetPublicKey(
    alias: String,
    platformSpecifics: PlatformCryptoOpts?
): KmmResult<CryptoPublicKey> {
    if (platformSpecifics == null || platformSpecifics !is JvmSpecifics) {
        throw InvalidParameterException(platformSpecifics, "JvmSpecifics required!")
    }
    return runCatching {
        CryptoPublicKey.fromJcaPublicKey(
            platformSpecifics.keyStore.getCertificateChain(alias).first().publicKey
        ).getOrThrow()
    }.wrap()
}

internal actual suspend fun doGetKeyPair(
    alias: String,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<CryptoKeyPair> {
    if (platformSpecifics !is JvmSpecifics) {
        throw InvalidParameterException(platformSpecifics, "JvmSpecifics required!")
    }
    return runCatching {
        (platformSpecifics.keyStore.getKey(alias, platformSpecifics.privateKeyPassword)
            ?: throw CryptoObjectNotFoundException("Key with $alias does not exist")) to doGetPublicKey(
            alias,
            platformSpecifics
        )
    }.mapCatching { (priv, pub) ->
        JvmPrivateKey(priv as PrivateKey, platformSpecifics) to pub.getOrThrow() as CryptoPublicKey.EC
    }.wrap()
}

internal actual suspend fun doStoreCertificateChain(
    alias: String,
    certs: CertificateChain,
    platformSpecifics: PlatformCryptoOpts?
): KmmResult<Unit> = runCatching {
    if (platformSpecifics !is JvmSpecifics) {
        throw InvalidParameterException(platformSpecifics, "JvmSpecifics required!")
    }

    val keyPairGenerator: KeyPairGenerator = //let's roll
        KeyPairGenerator.getInstance("EC", platformSpecifics.provider).apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }

    val kP = keyPairGenerator.generateKeyPair()

    platformSpecifics.keyStore.apply { load(null, null) }.let {
        it.setKeyEntry(
            alias,
            kP.private,
            null,
            certs.map { crtFactMut.withLock { certificateFactory.generateCertificate(it.encodeToDer().inputStream()) } }
                .toTypedArray()
        )
    }
}.wrap()


internal actual suspend fun doGetCertificateChain(
    alias: String,
    platformSpecifics: PlatformCryptoOpts?
): KmmResult<CertificateChain> = runCatching {
    if (platformSpecifics !is JvmSpecifics) {
        throw InvalidParameterException(platformSpecifics, "JvmSpecifics required!")
    }
    platformSpecifics.keyStore.getCertificateChain(alias).map { X509Certificate.decodeFromDer(it.encoded) }
}.wrap()
