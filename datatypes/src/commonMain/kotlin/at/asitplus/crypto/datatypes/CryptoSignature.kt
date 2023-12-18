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

    override fun toString(): String {
        return "CryptoSignature(signature=${signature.prettyPrint()})"
    }

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
     * Input is expected to be `r` and `s` values
     */
    class EC(private val rValue: ByteArray, private val sValue: ByteArray) : CryptoSignature(
        asn1Sequence {
            append(Asn1Primitive(INTEGER, rValue.dropWhile { it == 0x00.toByte() }.toByteArray()))
            append(Asn1Primitive(INTEGER, sValue.dropWhile { it == 0x00.toByte() }.toByteArray()))
        }
    ) {
        /**
         * JWS encodes an EC signature as the `r` and `s` value concatenated,
         * which may contain a padding (leading 0x00), which is dropped in the other constructor,
         * when creating the ASN.1 integers.
         */
        constructor(input: ByteArray) : this(
            input.sliceArray(0 until (input.size / 2)),
            input.sliceArray((input.size / 2) until input.size)
        )

        /**
         * Concatenates [rValue] and [sValue], padding each one to the next largest coordinate length
         * of an [EcCurve], for use in e.g. JWS signatures.
         */
        override val rawByteArray by lazy {
            val maxLenValues = max(rValue.size, sValue.size).toUInt()
            val correctLen = EcCurve.entries.map { it.coordinateLengthBytes }.filter { maxLenValues <= it }.min()
            rValue.ensureSize(correctLen) + sValue.ensureSize(correctLen)
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

        /**
         * In DER encoding, the first bit is the sign bit, so to encode numbers with the first bit set,
         * one needs to prepend a 0x00 padding byte. In this function, we'll drop that, to get the raw value.
         */
        @Throws(Asn1Exception::class)
        private fun dropFirstByteIfItIsPadding(src: Asn1Primitive): ByteArray {
            val decoded: ByteArray = src.decode(INTEGER) { it }
            if (decoded.size > 1 && decoded[0] == 0x00.toByte() && decoded[1] >= 0x80.toByte()) {
                return decoded.drop(1).toByteArray()
            }
            return decoded
        }
    }
}