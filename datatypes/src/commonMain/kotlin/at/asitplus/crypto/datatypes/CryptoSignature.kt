package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.Asn1Decodable
import at.asitplus.crypto.datatypes.asn1.Asn1Element
import at.asitplus.crypto.datatypes.asn1.Asn1Encodable
import at.asitplus.crypto.datatypes.asn1.Asn1Exception
import at.asitplus.crypto.datatypes.asn1.Asn1Primitive
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.BERTags.BIT_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.INTEGER
import at.asitplus.crypto.datatypes.asn1.DERTags.DER_SEQUENCE
import at.asitplus.crypto.datatypes.asn1.asn1Sequence
import at.asitplus.crypto.datatypes.asn1.decode
import at.asitplus.crypto.datatypes.asn1.encodeToTlvBitString
import at.asitplus.crypto.datatypes.asn1.ensureSize
import at.asitplus.crypto.datatypes.asn1.runRethrowing
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
import kotlin.math.max


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
    class EC(private val first: ByteArray, private val second: ByteArray) : CryptoSignature(
        asn1Sequence {
            append(Asn1Primitive(INTEGER, first.dropWhile { it == 0x00.toByte() }.toByteArray()))
            append(Asn1Primitive(INTEGER, second.dropWhile { it == 0x00.toByte() }.toByteArray()))
        }
    ) {
        constructor(input: ByteArray) : this(
            // TODO Better go through by hand at ensure the correct sizes
            input.sliceArray(0 until ((input.size + 1) / 2)),
            input.sliceArray(((input.size + 1) / 2) until input.size)
        )

        override val rawByteArray by lazy {
            val maxLen = max(first.size, second.size)
            first.ensureSize(maxLen.toUInt()) + second.ensureSize(maxLen.toUInt())
        }

        override fun encodeToTlvBitString(): Asn1Element = encodeToDer().encodeToTlvBitString()
    }

    class RSAorHMAC(input: ByteArray) : CryptoSignature(
        Asn1Primitive(BIT_STRING, input)
    ) {
        override val rawByteArray by lazy { (signature as Asn1Primitive).decode(BIT_STRING) { it } }
        override fun encodeToTlvBitString(): Asn1Element = this.encodeToTlv()
    }

    companion object : Asn1Decodable<Asn1Element, CryptoSignature> {
        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Element): CryptoSignature = runRethrowing {
            when (src.tag) {
                BIT_STRING -> RSAorHMAC((src as Asn1Primitive).decode(BIT_STRING) { it })
                DER_SEQUENCE -> {
                    src as Asn1Sequence
                    val first = dropFirstByteIfItIsPadding(src.nextChild() as Asn1Primitive)
                    val second = dropFirstByteIfItIsPadding(src.nextChild() as Asn1Primitive)
                    if (src.hasMoreChildren()) throw IllegalArgumentException("Illegal Signature Format")
                    EC(first, second)
                }

                else -> throw IllegalArgumentException("Unknown Signature Format")
            }
        }

        private fun dropFirstByteIfItIsPadding(src: Asn1Primitive): ByteArray {
            val decoded: ByteArray = src.decode(INTEGER) { it }
            if (decoded.size > 1) {
                if (decoded[0] == 0x00.toByte() && decoded[1] >= 0x80.toByte()) {
                    return decoded.drop(1).toByteArray()
                }
            }
            return decoded
        }
    }
}