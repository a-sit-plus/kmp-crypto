@file:OptIn(ExperimentalEncodingApi::class)

package at.asitplus.crypto.datatypes.asn1

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.JwsAlgorithm
import at.asitplus.crypto.datatypes.TbsCertificate
import at.asitplus.crypto.datatypes.asn1.JwsExtensions.encodeToByteArray
import at.asitplus.crypto.datatypes.asn1.JwsExtensions.ensureSize
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.datetime.Instant
import kotlin.io.encoding.ExperimentalEncodingApi

class SequenceBuilder {

    internal val elements = mutableListOf<ByteArray>()

    fun tagged(tag: Int, block: () -> ByteArray) = apply { elements += asn1Tag(tag, block()) }
    fun int(block: () -> Int) = apply { elements += block().encodeToAsn1() }
    fun long(block: () -> Long) = apply { elements += block().encodeToAsn1() }

    fun bitString(block: () -> ByteArray) = apply { elements += block().encodeToBitString() }

    fun oid(block: () -> String) = apply { elements += block().encodeToOid() }

    fun utf8String(block: () -> String) = apply { elements += asn1Tag(0x0c, block().encodeToByteArray()) }

    fun version(block: () -> Int) = apply { elements += asn1Tag(0xA0, block().encodeToAsn1()) }

    fun commonName(block: () -> String) = apply {
        oid { "550403" }
        utf8String { block() }
    }

    fun asn1null() = apply { elements += byteArrayOf(0x05.toByte(), 0x00.toByte()) }

    fun subjectPublicKey(block: () -> CryptoPublicKey) = apply { elements += block().encodeToAsn1() }

    fun tbsCertificate(block: () -> TbsCertificate) = apply { elements += block().encodeToDer() }

    fun sigAlg(block: () -> JwsAlgorithm) = apply { elements += block().encodeToAsn1() }

    fun utcTime(block: () -> Instant) = apply { elements += block().encodeToAsn1() }

    fun sequence(init: SequenceBuilder.() -> Unit) = apply {
        val seq = SequenceBuilder()
        seq.init()
        elements += asn1Tag(0x30, seq.elements.fold(byteArrayOf()) { acc, bytes -> acc + bytes })
    }


    fun set(init: SequenceBuilder.() -> Unit) = apply {
        val seq = SequenceBuilder()
        seq.init()
        elements += asn1Tag(0x31, seq.elements.fold(byteArrayOf()) { acc, bytes -> acc + bytes })
    }
}


fun sequence(init: SequenceBuilder.() -> Unit): ByteArray {
    val seq = SequenceBuilder()
    seq.init()
    return asn1Tag(0x30, seq.elements.fold(byteArrayOf()) { acc, bytes -> acc + bytes })
}

private fun Int.encodeToAsn1() = asn1Tag(0x02, encodeToDer())

private fun Int.encodeToDer() = encodeToByteArray().dropWhile { it == 0.toByte() }.toByteArray()

private fun Long.encodeToAsn1() = asn1Tag(0x02, encodeToDer())

private fun Long.encodeToDer() = encodeToByteArray().dropWhile { it == 0.toByte() }.toByteArray()

private fun ByteArray.encodeToBitString() = asn1Tag(0x03, (byteArrayOf(0x00) + this))

private fun asn1Tag(tag: Int, value: ByteArray) = byteArrayOf(tag.toByte()) + value.size.encodeLength() + value

private fun String.encodeToOid() = asn1Tag(0x06, decodeToByteArray(Base16()))

private fun Instant.encodeToAsn1(): ByteArray {
    val value = this.toString()
    if (value.isEmpty()) return asn1Tag(0x17, byteArrayOf())
    val matchResult = Regex("[0-9]{2}([0-9]{2})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})")
        .matchAt(value, 0)
        ?: throw IllegalArgumentException("instant serialization failed: $value")
    val year = matchResult.groups[1]?.value
        ?: throw IllegalArgumentException("instant serialization year failed: $value")
    val month = matchResult.groups[2]?.value
        ?: throw IllegalArgumentException("instant serialization month failed: $value")
    val day = matchResult.groups[3]?.value
        ?: throw IllegalArgumentException("instant serialization day failed: $value")
    val hour = matchResult.groups[4]?.value
        ?: throw IllegalArgumentException("instant serialization hour failed: $value")
    val minute = matchResult.groups[5]?.value
        ?: throw IllegalArgumentException("instant serialization minute failed: $value")
    val seconds = matchResult.groups[6]?.value
        ?: throw IllegalArgumentException("instant serialization seconds failed: $value")
    return asn1Tag(0x17, "$year$month$day$hour$minute${seconds}Z".encodeToByteArray())
}

fun JwsAlgorithm.Companion.decodeFromDer(input: ByteArray): JwsAlgorithm? {
    if (input.contentEquals("2A8648CE3D040302".encodeToOid()))
        return JwsAlgorithm.ES256
    return null
}

private fun JwsAlgorithm.encodeToAsn1() = when (this) {
    JwsAlgorithm.ES256 -> "2A8648CE3D040302".encodeToOid()
    else -> throw IllegalArgumentException("sigAlg: $this")
}

fun CryptoPublicKey.encodeToAsn1() = when (this) {
    is CryptoPublicKey.Ec -> sequence {
        sequence {
            oid { "2A8648CE3D0201" }
            when (curve) {
                EcCurve.SECP_256_R_1 -> oid { "2A8648CE3D030107" }
                EcCurve.SECP_384_R_1 -> oid { "2B81040022" }
                EcCurve.SECP_521_R_1 -> oid { "2B81040023" }
            }

        }
        bitString { (byteArrayOf(0x04.toByte()) + x.ensureSize(curve.coordinateLengthBytes) + y.ensureSize(curve.coordinateLengthBytes)) }
    }

    is CryptoPublicKey.Rsa -> {
        val key = sequence {
            tagged(0x02) {
                n.ensureSize(bits.number / 8u)
                    .let { if (it.first() == 0x00.toByte()) it else byteArrayOf(0x00, *it) }
            }
            int { e.toInt() }
        }
        sequence {

            sequence {
                oid { "2A864886F70D010101" }
                asn1null()
            }
            bitString {
                key
            }

        }
    }

}

private fun Int.encodeLength(): ByteArray {
    if (this < 128) {
        return byteArrayOf(this.toByte())
    }
    if (this < 0x100) {
        return byteArrayOf(0x81.toByte(), this.toByte())
    }
    if (this < 0x8000) {
        return byteArrayOf(0x82.toByte(), (this ushr 8).toByte(), this.toByte())
    }
    throw IllegalArgumentException("length $this")
}


object JwsExtensions {

    private const val ASN1_TAG_SEQUENCE = 0x30.toByte()
    private const val ASN1_TAG_INTEGER = 0x02.toByte()

    /**
     * Extracts the plain R and S values of an ECDSA signature
     * if it is wrapped in an ASN.1 Sequence of two ASN.1 Integers
     * (e.g. when computed in Java)
     */
    fun ByteArray.extractSignatureValues(expectedLength: Int): ByteArray {
        if (this[0] != ASN1_TAG_SEQUENCE) return this
        val sequenceLen = this[1]
        if (size != (2 + sequenceLen)) return this
        val rTag = this[2]
        if (rTag != ASN1_TAG_INTEGER) return this
        val rLength = this[3]
        if (size < 4 + rLength) return this
        val rStartIndex = 4
        val rEndIndex = rStartIndex + rLength
        val sTag = this[rEndIndex]
        if (sTag != ASN1_TAG_INTEGER) return this
        val sLength = this[rEndIndex + 1]
        if (size != (6 + rLength + sLength)) return this
        val sStartIndex = rEndIndex + 2
        val sEndIndex = sStartIndex + sLength
        val rValue = sliceArray(rStartIndex until rEndIndex)
        val sValue = sliceArray(sStartIndex until sEndIndex)
        val rValueRaw = rValue.stripLeadingSignByte().padWithZeros(expectedLength)
        val sValueRaw = sValue.stripLeadingSignByte().padWithZeros(expectedLength)
        return rValueRaw + sValueRaw
    }

    /**
     * JWS spec concatenates the R and S values,
     * but JCA needs an ASN.1 structure (SEQUENCE of two INTEGER) around it
     */
    fun ByteArray.convertToAsn1Signature(len: Int): ByteArray = if (size == len * 2) {
        val rValue = sliceArray(0 until len).toAsn1Integer()
        val sValue = sliceArray(len until len * 2).toAsn1Integer()
        val rAsn1Int = byteArrayOf(ASN1_TAG_INTEGER) + rValue.size.toByte() + rValue
        val sAsn1Int = byteArrayOf(ASN1_TAG_INTEGER) + sValue.size.toByte() + sValue
        byteArrayOf(ASN1_TAG_SEQUENCE) + (rAsn1Int.size + sAsn1Int.size).toByte() + rAsn1Int + sAsn1Int
    } else {
        this
    }

    /**
     * ASN.1 encoding about encoding of integers:
     * Bits of first octet and bit 8 of the second octet
     * shall not be all ones; and shall not be all zeros
     */
    private fun ByteArray.toAsn1Integer() = if (this[0] < 0) byteArrayOf(0) + this else
        if (this[0] == 0x00.toByte() && this[1] > 0) drop(1).toByteArray() else this

    /**
     * Encode the length of (as four bytes) plus the value itself
     */
    fun ByteArray?.encodeWithLength() = (this?.size ?: 0).encodeToByteArray() + (this ?: byteArrayOf())

    /**
     * Encode as a four-byte array
     */
    fun Int.encodeToByteArray(): ByteArray =
        byteArrayOf((this ushr 24).toByte(), (this ushr 16).toByte(), (this ushr 8).toByte(), (this).toByte())

    /**
     * Encode as a four-byte array
     */
    fun Long.encodeToByteArray(): ByteArray =
        byteArrayOf(
            (this ushr 56).toByte(), (this ushr 48).toByte(), (this ushr 40).toByte(), (this ushr 32).toByte(),
            (this ushr 24).toByte(), (this ushr 16).toByte(), (this ushr 8).toByte(), (this).toByte()
        )

    /**
     * Strips the leading 0x00 byte of an ASN.1-encoded Integer,
     * that will be there if the first bit of the value is set,
     * i.e. it is over 0x7F (or < 0 if it is signed)
     */
    fun ByteArray.stripLeadingSignByte() =
        if (this[0] == 0.toByte() && this[1] < 0) drop(1).toByteArray() else this

    /**
     * The extracted values from ASN.1 may be too short
     * to be simply concatenated as raw values,
     * so we'll need to pad them with 0x00 bytes to the expected length
     */
    fun ByteArray.padWithZeros(len: Int): ByteArray =
        if (size < len) ByteArray(len - size) { 0 } + this else this

    /**
     * Drops or adds zero bytes at the start until the [size] is reached
     */
    fun ByteArray.ensureSize(size: UInt): ByteArray = when {
        this.size.toUInt() > size -> this.drop(1).toByteArray().ensureSize(size)
        this.size.toUInt() < size -> (byteArrayOf(0) + this).ensureSize(size)
        else -> this
    }
}
