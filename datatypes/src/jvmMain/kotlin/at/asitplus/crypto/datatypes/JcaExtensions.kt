package at.asitplus.crypto.datatypes

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.asn1.ensureSize
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
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec


val CryptoAlgorithm.jcaName
    get() = when (this) {
        CryptoAlgorithm.ES256 -> "SHA256withECDSA"
        CryptoAlgorithm.ES384 -> "SHA384withECDSA"
        CryptoAlgorithm.ES512 -> "SHA512withECDSA"
        CryptoAlgorithm.HS256 -> "HmacSHA256"
        CryptoAlgorithm.HS384 -> "HmacSHA384"
        CryptoAlgorithm.HS512 -> "HmacSHA512"
        CryptoAlgorithm.RS256 -> "SHA256withRSA"
        CryptoAlgorithm.RS384 -> "SHA384withRSA"
        CryptoAlgorithm.RS512 -> "SHA512withRSA"
        CryptoAlgorithm.PS256 -> "RSASSA-PSS"
        CryptoAlgorithm.PS384 -> "RSASSA-PSS"
        CryptoAlgorithm.PS512 -> "RSASSA-PSS"
        CryptoAlgorithm.RS1 -> "SHA1withRSA"
    }

val CryptoAlgorithm.jcaParams
    get() = when (this) {
        CryptoAlgorithm.PS256 -> PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)

        CryptoAlgorithm.PS384 -> PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)

        CryptoAlgorithm.PS512 -> PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)

        else -> null
    }

val Digest.jcaName
    get() = when (this) {
        Digest.SHA256 -> "SHA-256"
        Digest.SHA384 -> "SHA-384"
        Digest.SHA512 -> "SHA-512"
        Digest.SHA1 -> "SHA-1"
    }

val EcCurve.jcaName
    get() = when (this) {
        EcCurve.SECP_256_R_1 -> "secp256r1"
        EcCurve.SECP_384_R_1 -> "secp384r1"
        EcCurve.SECP_521_R_1 -> "secp521r1"
    }

fun EcCurve.Companion.byJcaName(name: String): EcCurve? = EcCurve.entries.find { it.jcaName == name }


fun CryptoPublicKey.getJcaPublicKey() = when (this) {
    is CryptoPublicKey.Ec -> getJcaPublicKey()
    is CryptoPublicKey.Rsa -> getJcaPublicKey()
}

fun CryptoPublicKey.Ec.getJcaPublicKey(): KmmResult<ECPublicKey> {
    return runCatching {
        val parameterSpec = ECNamedCurveTable.getParameterSpec(curve.jwkName)
        val x = BigInteger(1, x)
        val y = BigInteger(1, y)
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

fun CryptoPublicKey.Ec.Companion.fromJcaPublicKey(publicKey: ECPublicKey): KmmResult<CryptoPublicKey> =
    runCatching {
        val curve = EcCurve.byJcaName(
            SECNamedCurves.getName(
                SubjectPublicKeyInfo.getInstance(
                    ASN1Sequence.getInstance(publicKey.encoded)
                ).algorithm.parameters as ASN1ObjectIdentifier
            )
        ) ?: throw SerializationException("Unknown Jca name")
        fromCoordinates(
            curve,
            publicKey.w.affineX.toByteArray().ensureSize(curve.coordinateLengthBytes),
            publicKey.w.affineY.toByteArray().ensureSize(curve.coordinateLengthBytes)
        )
    }.wrap()

fun CryptoPublicKey.Rsa.Companion.fromJcaPublicKey(publicKey: RSAPublicKey): KmmResult<CryptoPublicKey> =
    runCatching { CryptoPublicKey.Rsa(publicKey.modulus.toByteArray(), publicKey.publicExponent.toInt()) }.wrap()

fun CryptoPublicKey.Companion.fromJcaPublicKey(publicKey: PublicKey): KmmResult<CryptoPublicKey> =
    when (publicKey) {
        is RSAPublicKey -> CryptoPublicKey.Rsa.fromJcaPublicKey(publicKey)
        is ECPublicKey -> CryptoPublicKey.Ec.fromJcaPublicKey(publicKey)
        else -> KmmResult.failure(IllegalArgumentException("Unsupported Key Type"))
    }


val CryptoSignature.jcaSignatureBytes: ByteArray
    get() = when (this) {
        is CryptoSignature.EC -> encodeToDer()
        is CryptoSignature.RSAorHMAC -> rawByteArray
    }

