package at.asitplus.crypto.datatypes.pki

import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.asn1.Asn1Decodable
import at.asitplus.crypto.datatypes.asn1.Asn1Encodable
import at.asitplus.crypto.datatypes.asn1.Asn1Exception
import at.asitplus.crypto.datatypes.asn1.Asn1Primitive
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.Asn1Set
import at.asitplus.crypto.datatypes.asn1.Asn1StructuralException
import at.asitplus.crypto.datatypes.asn1.Asn1Tagged
import at.asitplus.crypto.datatypes.asn1.KnownOIDs
import at.asitplus.crypto.datatypes.asn1.asn1Sequence
import at.asitplus.crypto.datatypes.asn1.readBitString
import at.asitplus.crypto.datatypes.asn1.readInt
import at.asitplus.crypto.datatypes.asn1.runRethrowing
import at.asitplus.crypto.datatypes.asn1.verifyTag
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import kotlinx.serialization.Serializable

/**
 * The meat of a PKCS#10 Certification Request:
 * The structure that gets signed
 * @param version defaults to 0
 * @param subjectName list of subject distinguished names
 * @param publicKey nomen est omen
 * @param attributes nomen est omen
 */
@Serializable
data class TbsCertificationRequest(
    val version: Int = 0,
    val subjectName: List<RelativeDistinguishedName>,
    val publicKey: CryptoPublicKey,
    val attributes: List<Pkcs10CertificationRequestAttribute>? = null
) : Asn1Encodable<Asn1Sequence> {

    /**
     * Convenience constructor for adding [X509CertificateExtension]`s` to a CSR (in addition to generic attributes
     *
     * @throws IllegalArgumentException if no extensions are provided
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey,
        extensions: List<X509CertificateExtension>,
        version: Int = 0,
        attributes: List<Pkcs10CertificationRequestAttribute>? = null,
    ) : this(version, subjectName, publicKey, mutableListOf<Pkcs10CertificationRequestAttribute>().also { attrs ->
        if (extensions.isEmpty()) throw IllegalArgumentException("No extensions provided!")
        attributes?.let { attrs.addAll(it) }
        attrs.add(Pkcs10CertificationRequestAttribute(KnownOIDs.extensionRequest, asn1Sequence {
            extensions.forEach { append(it) }
        }))
    })

    override fun encodeToTlv() = asn1Sequence {
        int(version)
        sequence { subjectName.forEach { append(it) } }

        //subject Public Key
        append(publicKey)
        tagged(0u) { attributes?.map { append(it) } }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as TbsCertificationRequest

        if (version != other.version) return false
        if (subjectName != other.subjectName) return false
        if (publicKey != other.publicKey) return false
        if (attributes != other.attributes) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + subjectName.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + (attributes?.hashCode() ?: 0)
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, TbsCertificationRequest> {
        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence) = runRethrowing {
            val version = (src.nextChild() as Asn1Primitive).readInt()
            val subject = (src.nextChild() as Asn1Sequence).children.map {
                RelativeDistinguishedName.decodeFromTlv(it as Asn1Set)
            }
            val cryptoPublicKey = CryptoPublicKey.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val attributes = if (src.hasMoreChildren()) {
                (src.nextChild() as Asn1Tagged).verifyTag(0u)
                    .map { Pkcs10CertificationRequestAttribute.decodeFromTlv(it as Asn1Sequence) }
            } else null

            if (src.hasMoreChildren()) throw Asn1StructuralException("Superfluous Data in CSR Structure")

            TbsCertificationRequest(
                version = version,
                subjectName = subject,
                publicKey = cryptoPublicKey,
                attributes = attributes,
            )
        }
    }
}


/**
 * Very simple implementation of a PKCS#10 Certification Request
 */
@Serializable
data class Pkcs10CertificationRequest(
    val tbsCsr: TbsCertificationRequest,
    val signatureAlgorithm: CryptoAlgorithm,
    @Serializable(with = ByteArrayBase64Serializer::class)
    val signature: ByteArray
) : Asn1Encodable<Asn1Sequence> {


    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = asn1Sequence {
        append(tbsCsr)
        append(signatureAlgorithm)
        bitString(signature)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Pkcs10CertificationRequest

        if (tbsCsr != other.tbsCsr) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCsr.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, Pkcs10CertificationRequest> {

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence): Pkcs10CertificationRequest = runRethrowing {
            val tbsCsr = TbsCertificationRequest.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val sigAlg = CryptoAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val signature = (src.nextChild() as Asn1Primitive).readBitString()
            if (src.hasMoreChildren()) throw Asn1StructuralException("Superfluous structure in CSR Structure")
            return Pkcs10CertificationRequest(tbsCsr, sigAlg, signature.rawBytes)
        }
    }
}
