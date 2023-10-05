package at.asitplus.crypto.datatypes

import kotlinx.datetime.Instant

class Asn1Reader(input: ByteArray) {

    var rest = input

    fun <T> read(tag: Int, func: (ByteArray) -> T?): T {
        val past = read(rest, tag, func)
        rest = past.second
        return past.first
    }

}

fun <T> read(input: ByteArray, tag: Int, func: (ByteArray) -> T?): Pair<T, ByteArray> {
    val tlv = input.readTlv()
    if (tlv.tag != tag.toByte()) throw IllegalArgumentException("Expected tag $tag, got ${tlv.tag}")
    val obj = runCatching { func(tlv.content) }.getOrNull() ?: throw IllegalArgumentException("Can't decode content")
    if (tlv.overallLength > input.size) throw IllegalArgumentException("Out of bytes")
    val rest = input.drop(tlv.overallLength).toByteArray()
    return Pair(obj, rest)
}

fun decodeBitstring(input: ByteArray) = input.drop(1).toByteArray()

fun CryptoPublicKey.Ec.Companion.decodeFromDer(input: ByteArray): CryptoPublicKey.Ec? = runCatching {
    var rest = input
    // TODO support other types
    val firstSequence = read(rest, 0x30, { bytes -> bytes }).also { rest = it.second }
    val bitString = read(rest, 0x03, ::decodeBitstring).also { rest = it.second }
    val xAndY = bitString.first.drop(1).toByteArray()
    val x = xAndY.take(32).toByteArray()
    val y = xAndY.drop(32).take(32).toByteArray()
    return CryptoPublicKey.Ec.fromCoordinates(EcCurve.SECP_256_R_1, x, y)
}.getOrNull()

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

fun ByteArray.readTlv(): TLV {
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


fun ByteArray.readTag(tag: Byte) =
    if (this.isNotEmpty() && this[0] == tag) this.drop(1).toByteArray() else null

fun ByteArray.readTag(tag: Int) =
    if (this.isNotEmpty() && this[0] == tag.toByte()) this.drop(1).toByteArray() else null

data class TLV(val tag: Byte, val length: Int, val content: ByteArray, val overallLength: Int)
