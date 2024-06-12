package at.asitplus.crypto.datatypes

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.pki.X509Certificate
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.SerializationException
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.JCEECPublicKey
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec

private val certificateFactoryMutex = Mutex()
private val certFactory = CertificateFactory.getInstance("X.509")

val X509SignatureAlgorithm.jcaName
    get() = when (this) {
        X509SignatureAlgorithm.ES256 -> "SHA256withECDSA"
        X509SignatureAlgorithm.ES384 -> "SHA384withECDSA"
        X509SignatureAlgorithm.ES512 -> "SHA512withECDSA"
        X509SignatureAlgorithm.HS256 -> "HmacSHA256"
        X509SignatureAlgorithm.HS384 -> "HmacSHA384"
        X509SignatureAlgorithm.HS512 -> "HmacSHA512"
        X509SignatureAlgorithm.RS256 -> "SHA256withRSA"
        X509SignatureAlgorithm.RS384 -> "SHA384withRSA"
        X509SignatureAlgorithm.RS512 -> "SHA512withRSA"
        X509SignatureAlgorithm.PS256 -> "RSASSA-PSS"
        X509SignatureAlgorithm.PS384 -> "RSASSA-PSS"
        X509SignatureAlgorithm.PS512 -> "RSASSA-PSS"
        X509SignatureAlgorithm.RS1 -> "SHA1withRSA"
    }

val X509SignatureAlgorithm.jcaParams
    get() = when (this) {
        X509SignatureAlgorithm.PS256 -> PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)

        X509SignatureAlgorithm.PS384 -> PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)

        X509SignatureAlgorithm.PS512 -> PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)

        else -> null
    }

val Digest.jcaName
    get() = when (this) {
        Digest.SHA256 -> "SHA-256"
        Digest.SHA384 -> "SHA-384"
        Digest.SHA512 -> "SHA-512"
        Digest.SHA1 -> "SHA-1"
    }


val Digest?.jcaAlgorithmComponent get() = when (this) {
    null -> "None"
    Digest.SHA1 -> "SHA1"
    Digest.SHA256 -> "SHA256"
    Digest.SHA384 -> "SHA384"
    Digest.SHA512 -> "SHA512"
}

val ECCurve.jcaName
    get() = when (this) {
        ECCurve.SECP_256_R_1 -> "secp256r1"
        ECCurve.SECP_384_R_1 -> "secp384r1"
        ECCurve.SECP_521_R_1 -> "secp521r1"
    }

fun ECCurve.Companion.byJcaName(name: String): ECCurve? = ECCurve.entries.find { it.jcaName == name }


fun CryptoPublicKey.getJcaPublicKey() = when (this) {
    is CryptoPublicKey.EC -> getJcaPublicKey()
    is CryptoPublicKey.Rsa -> getJcaPublicKey()
}

fun CryptoPublicKey.EC.getJcaPublicKey(): KmmResult<ECPublicKey> {
    return runCatching {
        val parameterSpec = ECNamedCurveTable.getParameterSpec(curve.jwkName)
        val x = x.residue.toJavaBigInteger()
        val y = y.residue.toJavaBigInteger()
        val ecPoint = parameterSpec.curve.createPoint(x, y)
        val ecPublicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)
        JCEECPublicKey("EC", ecPublicKeySpec)
    }.wrap()
}

private val rsaFactory = KeyFactory.getInstance("RSA")

fun CryptoPublicKey.Rsa.getJcaPublicKey(): KmmResult<RSAPublicKey> =
    runCatching {
        rsaFactory.generatePublic(
            RSAPublicKeySpec(BigInteger(1, n), BigInteger.valueOf(e.toLong()))
        ) as RSAPublicKey
    }.wrap()

fun CryptoPublicKey.EC.Companion.fromJcaPublicKey(publicKey: ECPublicKey): KmmResult<CryptoPublicKey> =
    runCatching {
        val curve = ECCurve.byJcaName(
            SECNamedCurves.getName(
                SubjectPublicKeyInfo.getInstance(
                    ASN1Sequence.getInstance(publicKey.encoded)
                ).algorithm.parameters as ASN1ObjectIdentifier
            )
        ) ?: throw SerializationException("Unknown Jca name")
        CryptoPublicKey.EC(
            curve,
            publicKey.w.affineX.toByteArray(),
            publicKey.w.affineY.toByteArray()
        )
    }.wrap()

fun CryptoPublicKey.Rsa.Companion.fromJcaPublicKey(publicKey: RSAPublicKey): KmmResult<CryptoPublicKey> =
    runCatching { CryptoPublicKey.Rsa(publicKey.modulus.toByteArray(), publicKey.publicExponent.toInt()) }.wrap()

fun CryptoPublicKey.Companion.fromJcaPublicKey(publicKey: PublicKey): KmmResult<CryptoPublicKey> =
    when (publicKey) {
        is RSAPublicKey -> CryptoPublicKey.Rsa.fromJcaPublicKey(publicKey)
        is ECPublicKey -> CryptoPublicKey.EC.fromJcaPublicKey(publicKey)
        else -> KmmResult.failure(IllegalArgumentException("Unsupported Key Type"))
    }

/**
 * In Java EC signatures are returned as DER-encoded, RSA signatures however are raw bytearrays
 */
val CryptoSignature.jcaSignatureBytes: ByteArray
    get() = when (this) {
        is CryptoSignature.EC -> encodeToDer()
        is CryptoSignature.RSAorHMAC -> rawByteArray
    }

/**
 * In Java EC signatures are returned as DER-encoded, RSA signatures however are raw bytearrays
 */
fun CryptoSignature.Companion.parseFromJca(input: ByteArray, algorithm: X509SignatureAlgorithm) =
    if (algorithm.isEc)
        CryptoSignature.EC.decodeFromDer(input)
    else
        CryptoSignature.RSAorHMAC(input)

/**
 * Converts this [X509Certificate] to a [java.security.cert.X509Certificate].
 * This function is suspending, because it uses a mutex to lock the underlying certificate factory (which is reused for performance reasons
 */
suspend fun X509Certificate.toJcaCertificate(): KmmResult<java.security.cert.X509Certificate> = runCatching {
    certificateFactoryMutex.withLock {
        certFactory.generateCertificate(encodeToDer().inputStream()) as java.security.cert.X509Certificate
    }
}.wrap()

/**
 * blocking implementation of [toJcaCertificate]
 */
fun X509Certificate.toJcaCertificateBlocking(): KmmResult<java.security.cert.X509Certificate> =
    runBlocking { toJcaCertificate() }

/**
 * Converts this [java.security.cert.X509Certificate] to an [X509Certificate]
 */
fun java.security.cert.X509Certificate.toKmpCertificate() =
    runCatching { X509Certificate.decodeFromDer(encoded) }.wrap()