package at.asitplus.crypto.datatypes

import at.asitplus.KmmResult
import at.asitplus.catching
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
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec

private val certificateFactoryMutex = Mutex()
private val certFactory = CertificateFactory.getInstance("X.509")

val Digest.jcaPSSParams
    get() = when (this) {
        Digest.SHA1 -> PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1)
        Digest.SHA256 -> PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
        Digest.SHA384 -> PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)
        Digest.SHA512 -> PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)
    }

private fun sigGetInstance(alg: String, provider: String?) =
    when (provider) {
        null -> Signature.getInstance(alg)
        else -> Signature.getInstance(alg, provider)
    }
/** Get a pre-configured JCA instance for this algorithm */
fun SignatureAlgorithm.getJCASignatureInstance(provider: String? = null, isAndroid: Boolean = false) = catching {
    when (this) {
        is SignatureAlgorithm.ECDSA ->
            sigGetInstance("${this.digest.jcaAlgorithmComponent}withECDSA", provider)
        is SignatureAlgorithm.HMAC ->
            sigGetInstance("Hmac${this.digest.jcaAlgorithmComponent}", provider)
        is SignatureAlgorithm.RSA -> when (this.padding) {
            RSAPadding.PKCS1 ->
                sigGetInstance("${this.digest.jcaAlgorithmComponent}withRSA", provider)
            RSAPadding.PSS -> when (isAndroid) {
                true ->
                    sigGetInstance("${this.digest.jcaAlgorithmComponent}withRSA/PSS", provider)
                false ->
                    sigGetInstance("RSASSA-PSS", provider).also {
                        it.setParameter(this.digest.jcaPSSParams)
                    }
            }
        }
    }
}
/** Get a pre-configured JCA instance for this algorithm */
fun SpecializedSignatureAlgorithm.getJCASignatureInstance(provider: String? = null) =
    this.algorithm.getJCASignatureInstance(provider)

val Digest.jcaName
    get() = when (this) {
        Digest.SHA256 -> "SHA-256"
        Digest.SHA384 -> "SHA-384"
        Digest.SHA512 -> "SHA-512"
        Digest.SHA1 -> "SHA-1"
    }


val Digest?.jcaAlgorithmComponent get() = when (this) {
    null -> "NONE"
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

fun CryptoPublicKey.EC.getJcaPublicKey(): KmmResult<ECPublicKey> = catching {
    val parameterSpec = ECNamedCurveTable.getParameterSpec(curve.jwkName)
    val x = x.residue.toJavaBigInteger()
    val y = y.residue.toJavaBigInteger()
    val ecPoint = parameterSpec.curve.createPoint(x, y)
    val ecPublicKeySpec = ECPublicKeySpec(ecPoint, parameterSpec)
    JCEECPublicKey("EC", ecPublicKeySpec)

}

private val rsaFactory = KeyFactory.getInstance("RSA")

fun CryptoPublicKey.Rsa.getJcaPublicKey(): KmmResult<RSAPublicKey> = catching {
    rsaFactory.generatePublic(
        RSAPublicKeySpec(BigInteger(1, n), BigInteger.valueOf(e.toLong()))
    ) as RSAPublicKey
}

fun CryptoPublicKey.EC.Companion.fromJcaPublicKey(publicKey: ECPublicKey): KmmResult<CryptoPublicKey> = catching {
    val curve = ECCurve.byJcaName(
        SECNamedCurves.getName(
            SubjectPublicKeyInfo.getInstance(
                ASN1Sequence.getInstance(publicKey.encoded)
            ).algorithm.parameters as ASN1ObjectIdentifier
        )
    ) ?: throw SerializationException("Unknown Jca name")
    fromUncompressed(
        curve,
        publicKey.w.affineX.toByteArray(),
        publicKey.w.affineY.toByteArray()
    )
}

fun CryptoPublicKey.Rsa.Companion.fromJcaPublicKey(publicKey: RSAPublicKey): KmmResult<CryptoPublicKey> =
    catching { CryptoPublicKey.Rsa(publicKey.modulus.toByteArray(), publicKey.publicExponent.toInt()) }

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
fun CryptoSignature.Companion.parseFromJca(
    input: ByteArray,
    algorithm: SignatureAlgorithm
): CryptoSignature =
    if (algorithm is SignatureAlgorithm.ECDSA)
        CryptoSignature.EC.parseFromJca(input)
    else
        CryptoSignature.RSAorHMAC.parseFromJca(input)

fun CryptoSignature.Companion.parseFromJca(
    input: ByteArray,
    algorithm: SpecializedSignatureAlgorithm
) = parseFromJca(input, algorithm.algorithm)

/**
 * Parses a signature produced by the JCA digestwithECDSA algorithm.
 */
fun CryptoSignature.EC.Companion.parseFromJca(input: ByteArray) =
    CryptoSignature.EC.decodeFromDer(input)

/**
 * Parses a signature produced by the JCA digestWithECDSAinP1363Format algorithm.
 */
fun CryptoSignature.EC.Companion.parseFromJcaP1363(input: ByteArray) =
    CryptoSignature.EC.fromRawBytes(input)

fun CryptoSignature.RSAorHMAC.Companion.parseFromJca(input: ByteArray) =
    CryptoSignature.RSAorHMAC(input)

/**
 * Converts this [X509Certificate] to a [java.security.cert.X509Certificate].
 * This function is suspending, because it uses a mutex to lock the underlying certificate factory (which is reused for performance reasons
 */
suspend fun X509Certificate.toJcaCertificate(): KmmResult<java.security.cert.X509Certificate> = catching {
    certificateFactoryMutex.withLock {
        certFactory.generateCertificate(encodeToDer().inputStream()) as java.security.cert.X509Certificate
    }
}

/**
 * blocking implementation of [toJcaCertificate]
 */
fun X509Certificate.toJcaCertificateBlocking(): KmmResult<java.security.cert.X509Certificate> =
    runBlocking { toJcaCertificate() }

/**
 * Converts this [java.security.cert.X509Certificate] to an [X509Certificate]
 */
fun java.security.cert.X509Certificate.toKmpCertificate() =
    catching { X509Certificate.decodeFromDer(encoded) }