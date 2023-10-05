package at.asitplus.crypto.datatypes

import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Instant

class Asn1Reader(input: ByteArray) {

    var rest = input

    fun <T> readSequence(func: (ByteArray) -> T?) = read(0x30, func)

    fun <T> readSet(func: (ByteArray) -> T?) = read(0x31, func)

    fun readOid() = read(0x06) { bytes -> bytes.encodeToString(Base16) }

    fun readBitstring() = read(0x03, ::decodeBitstring)

    fun readInt() = read(0x02, Int.Companion::decodeFromDer)

    fun readLong() = read(0x02, Long.Companion::decodeFromDer)

    fun readInstant() = read(0x17, Instant.Companion::decodeFromDer)

    fun readUtf8String() = read(0x0c) { bytes -> String(bytes) }

    fun <T> read(tag: Int, func: (ByteArray) -> T?): T {
        val tlv = rest.readTlv()
        if (tlv.tag != tag.toByte())
            throw IllegalArgumentException("Expected tag $tag, got ${tlv.tag}")
        val obj = runCatching { func(tlv.content) }.getOrNull()
            ?: throw IllegalArgumentException("Can't decode content")
        if (tlv.overallLength > rest.size)
            throw IllegalArgumentException("Out of bytes")
        rest = rest.drop(tlv.overallLength).toByteArray()
        return obj
    }


}


fun decodeBitstring(input: ByteArray) = input.drop(1).toByteArray()

fun CryptoPublicKey.Ec.Companion.decodeFromDer(input: ByteArray): CryptoPublicKey.Ec? = runCatching {
    val reader = Asn1Reader(input)
    val ecCurve = reader.readSequence(::decodePublicKeyType)
    val bitString = reader.readBitstring()
    val xAndY = bitString.drop(1).toByteArray()
    val x = xAndY.take(32).toByteArray()
    val y = xAndY.drop(32).take(32).toByteArray()
    return CryptoPublicKey.Ec.fromCoordinates(ecCurve, x, y)
}.getOrNull()

fun decodePublicKeyType(input: ByteArray): EcCurve {
    val reader = Asn1Reader(input)
    val oid = reader.readOid()
    if (oid == "2A8648CE3D0201") {
        val curveOid = reader.readOid()
        return when (curveOid) {
            "2A8648CE3D030107" -> EcCurve.SECP_256_R_1
            "2B81040022" -> EcCurve.SECP_384_R_1
            "2B81040023" -> EcCurve.SECP_521_R_1
            else -> throw IllegalArgumentException("Curve not supported: " + curveOid)
        }
    } else {
        throw IllegalArgumentException("Non-EC Keys not supported")
    }
}

fun Instant.Companion.decodeFromDer(input: ByteArray): Instant? {
    val s = String(input)
    val isoString =
        "20${s[0]}${s[1]}-${s[2]}${s[3]}-${s[4]}${s[5]}T${s[6]}${s[7]}:${s[8]}${s[9]}:${s[10]}${s[11]}${s[12]}"
    return Instant.parse(isoString)
}

fun Int.Companion.decodeFromDer(input: ByteArray): Int {
    var result = 0
    for (i in input.indices) {
        result = (result shl Byte.SIZE_BITS) or (input[i].toUByte().toInt())
    }
    return result
}

fun Long.Companion.decodeFromDer(input: ByteArray): Long {
    var result = 0L
    for (i in input.indices) {
        result = (result shl Byte.SIZE_BITS) or (input[i].toUByte().toLong())
    }
    return result
}

private fun ByteArray.readTlv(): TLV {
    if (this.isEmpty()) throw IllegalArgumentException("Can't read TLV, input empty")
    val tag = this[0]
    val firstLength = this[1]
    if (firstLength == 0x82.toByte()) {
        if (this.size < 4) throw IllegalArgumentException("Can't decode length")
        val length = (this[2].toUByte().toInt() shl 8) + this[3].toUByte().toInt()
        if (this.size < 4 + length) throw IllegalArgumentException("Out of bytes")
        val value = this.drop(4).take(length).toByteArray()
        return TLV(tag, length, value, 4 + length)
    }
    if (firstLength == 0x81.toByte()) {
        if (this.size < 3) throw IllegalArgumentException("Can't decode length")
        val length = this[2].toUByte().toInt()
        if (this.size < 3 + length) throw IllegalArgumentException("Out of bytes")
        val value = this.drop(3).take(length).toByteArray()
        return TLV(tag, length, value, 3 + length)
    }
    val length = firstLength.toInt()
    if (this.size < 2 + length) throw IllegalArgumentException("Out of bytes")
    val value = this.drop(2).take(length).toByteArray()
    return TLV(tag, length, value, 2 + length)
}


data class TLV(val tag: Byte, val length: Int, val content: ByteArray, val overallLength: Int)
