package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.asn1.BERTags.INTEGER
import at.asitplus.crypto.datatypes.asn1.BERTags.BIT_STRING
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Contextual
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


/**
 * Data class which holds Asn1 Encoding of a signature of a specified algorithm
 * Allows simple ASN1 - Raw transformation of signature values
 * Does not check for anything!
 */

@Serializable(with = CryptoSignature.CryptoSignatureSerializer::class)
sealed class CryptoSignature(
    @Contextual
    protected val signature: Asn1Element,
) : Asn1Encodable<Asn1Element> {

    /**
     * Removes ASN1 Structure and returns the value(s) as ByteArray
     */
    abstract val rawByteArray: ByteArray

    fun serialize(): String = signature.derEncoded.encodeToString(Base64UrlStrict)

    abstract fun encodeToTlvBitString(): Asn1Element

    abstract val signatureBytes :ByteArray

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CryptoSignature

        return signature == other.signature
    }

    override fun hashCode(): Int = signature.hashCode()

    override fun encodeToTlv(): Asn1Element = signature

    object CryptoSignatureSerializer : KSerializer<CryptoSignature> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor("CryptoSignature", PrimitiveKind.STRING)

        override fun deserialize(decoder: Decoder): RSAorHMAC =
            RSAorHMAC(decoder.decodeString().encodeToByteArray())

        override fun serialize(encoder: Encoder, value: CryptoSignature) {
            encoder.encodeString(value.serialize())
        }
    }

    /**
     * Input is expected to be x,y coordinates concatenated to bytearray
     */
    class EC(input: ByteArray) : CryptoSignature(
        asn1Sequence {
            append(
                Asn1Primitive(
                    INTEGER,
                    input.sliceArray(0 until (input.size / 2))
                )
            )
            append(
                Asn1Primitive(
                    INTEGER,
                    input.sliceArray((input.size / 2) until input.size)
                )
            )
        }
    ) {
        override val rawByteArray by lazy {
            val coordSizes = listOf(
                32 - 1,
                48 - 1,
                66 - 1
            ) // 256, 384, 521 -- note that 521 gets rounded up to 528 -- Minus 1 since arrays start at 0
            val coordSize =
                coordSizes.filter { it <= ((signature as Asn1Sequence).children[0] as Asn1Primitive).content.size }
                    .minOrNull() ?: throw Exception("Illegal signature length")
            byteArrayOf(
                *((signature as Asn1Sequence).children[0] as Asn1Primitive).decode(INTEGER) { it }
                    .padWithZeros(coordSize),
                *(signature.children[1] as Asn1Primitive).decode(INTEGER) { it }.padWithZeros(coordSize)
            )
        }

        override fun encodeToTlvBitString(): Asn1Element = encodeToDer().encodeToTlvBitString()

        override val signatureBytes: ByteArray
            get() = encodeToDer()

    }

    class RSAorHMAC(input: ByteArray) : CryptoSignature(
        Asn1Primitive(BIT_STRING, input)
    ) {
        override val rawByteArray by lazy { (signature as Asn1Primitive).decode(BIT_STRING) { it } }
        override fun encodeToTlvBitString(): Asn1Element = this.encodeToTlv()

        override val signatureBytes: ByteArray
            get() = rawByteArray
    }

    companion object : Asn1Decodable<Asn1Element, CryptoSignature> {
        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Element): CryptoSignature =
            runRethrowing {
                when (src.tag) {
                    BIT_STRING -> RSAorHMAC((src as Asn1Primitive).decode(BIT_STRING) { it })
                    DERTags.DER_SEQUENCE -> {
                        val first =
                            ((src as Asn1Sequence).nextChild() as Asn1Primitive).decode(INTEGER) { it.dropWhile { it == 0.toByte() } } //The problems are somehow related to this
                                .toByteArray()
                        val second =
                            (src.nextChild() as Asn1Primitive).decode(INTEGER) { it.dropWhile { it == 0.toByte() } }
                                .toByteArray()
                        if (src.hasMoreChildren()) throw IllegalArgumentException("Illegal Signature Format")
                        EC(first + second)
                    }

                    else -> throw IllegalArgumentException("Unknown Signature Format")
                }
            }
    }
}