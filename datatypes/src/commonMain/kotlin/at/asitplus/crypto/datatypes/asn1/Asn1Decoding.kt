package at.asitplus.crypto.datatypes.asn1

import at.asitplus.crypto.datatypes.asn1.BERTags.BMP_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.GENERALIZED_TIME
import at.asitplus.crypto.datatypes.asn1.BERTags.IA5_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.INTEGER
import at.asitplus.crypto.datatypes.asn1.BERTags.NULL
import at.asitplus.crypto.datatypes.asn1.BERTags.NUMERIC_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.OCTET_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.PRINTABLE_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.T61_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.UNIVERSAL_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.UTC_TIME
import at.asitplus.crypto.datatypes.asn1.BERTags.UTF8_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.VISIBLE_STRING
import at.asitplus.crypto.datatypes.asn1.DERTags.isContainer
import at.asitplus.crypto.datatypes.asn1.DERTags.toExplicitTag
import kotlinx.datetime.Instant
import kotlin.experimental.and


/**
 * Parses the provides [input] into a single [Asn1Element]
 * @return the parsed [Asn1Element]
 *
 * @throws Asn1Exception on invalid input or if more than a single root structure was contained in the [input]
 */
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parse(input: ByteArray) = Asn1Reader(input).doParse().let {
    if (it.size != 1) throw Asn1StructuralException("Multiple ASN.1 structures found")
    it.first()
}

private class Asn1Reader(input: ByteArray) {

    private var rest = input

    @Throws(Asn1Exception::class)
    fun doParse(): List<Asn1Element> = runRethrowing {
        val result = mutableListOf<Asn1Element>()
        while (rest.isNotEmpty()) {
            val tlv = read()
            if (tlv.isSequence()) result.add(Asn1Sequence(Asn1Reader(tlv.content).doParse()))
            else if (tlv.isSet()) result.add(Asn1Set(Asn1Reader(tlv.content).doParse()))
            else if (tlv.isExplicitlyTagged()) result.add(
                Asn1Tagged(
                    tlv.tag,
                    Asn1Reader(tlv.content).doParse()
                )
            )
            else if (tlv.tag == OCTET_STRING) {
                runCatching {
                    result.add(Asn1EncapsulatingOctetString(Asn1Reader(tlv.content).doParse()))
                }.getOrElse { result.add(Asn1PrimitiveOctetString(tlv.content)) }
            } else result.add(Asn1Primitive(tlv.tag, tlv.content))

        }
        return result
    }

    private fun TLV.isSet() = tag == DERTags.DER_SET
    private fun TLV.isSequence() = tag == DERTags.DER_SEQUENCE
    private fun TLV.isExplicitlyTagged() =
        tag.isContainer() //yes, this includes sequences and set, so we need to check this last!

    @Throws(Asn1Exception::class)
    private fun read(): TLV = runRethrowing {
        val tlv = rest.readTlv()
        if (tlv.overallLength > rest.size)
            throw Asn1Exception("Out of bytes")
        rest = rest.drop(tlv.overallLength).toByteArray()
        return tlv
    }
}

/**
 * decodes this [Asn1Primitive]'s content into an [Int]
 *
 * @throws [Throwable] all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readInt() = runRethrowing { decode(INTEGER) { Int.decodeFromDer(it) } }

/**
 * Exception-free version of [readInt]
 */
fun Asn1Primitive.readIntOrNull() = runCatching { readInt() }.getOrNull()


/**
 * decodes this [Asn1Primitive]'s content into a [Long]
 *
 * @throws [Throwable] all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readLong() = runRethrowing { decode(INTEGER) { Long.decodeFromDer(it) } }

/**
 * Exception-free version of [readLong]
 */
fun Asn1Primitive.readLongOrNull() = runCatching { readLong() }.getOrNull()


/**
 * decodes this [Asn1Primitive]'s content into an [Asn1String]
 *
 * @throws [Throwable] all sorts of exceptions on invalid input
 */
@Throws(Throwable::class)
fun Asn1Primitive.readString(): Asn1String = runRethrowing {
    if (tag == UTF8_STRING) Asn1String.UTF8(content.decodeToString())
    else if (tag == UNIVERSAL_STRING) Asn1String.Universal(content.decodeToString())
    else if (tag == IA5_STRING) Asn1String.IA5(content.decodeToString())
    else if (tag == BMP_STRING) Asn1String.BMP(content.decodeToString())
    else if (tag == T61_STRING) Asn1String.Teletex(content.decodeToString())
    else if (tag == PRINTABLE_STRING) Asn1String.Printable(content.decodeToString())
    else if (tag == NUMERIC_STRING) Asn1String.Numeric(content.decodeToString())
    else if (tag == VISIBLE_STRING) Asn1String.Visible(content.decodeToString())
    else TODO("Support other string tag $tag")
}

/**
 * Exception-free version of [readString]
 */
fun Asn1Primitive.readStringOrNull() = runCatching { readString() }.getOrNull()


/**
 * decodes this [Asn1Primitive]'s content into an [Instant] if it is encoded as UTC TIME or GENERALIZED TIME
 *
 * @throws Asn1Exception on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readInstant() =
    if (tag == UTC_TIME) decode(UTC_TIME, Instant.Companion::decodeUtcTimeFromDer)
    else if (tag == GENERALIZED_TIME) decode(GENERALIZED_TIME, Instant.Companion::decodeGeneralizedTimeFromDer)
    else TODO("Support time tag $tag")

/**
 * Exception-free version of [readInstant]
 */
fun Asn1Primitive.readInstantOrNull() = runCatching { readInstant() }.getOrNull()


/**
 * decodes this [Asn1Primitive]'s content into an [ByteArray], assuming it was encoded as BIT STRING
 *
 * @throws Asn1Exception  on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readBitString() = Asn1BitString.decodeFromTlv(this)

/**
 * Exception-free version of [readBitString]
 */
fun Asn1Primitive.readBitStringOrNull() = runCatching { readBitString() }.getOrNull()


/**
 * decodes this [Asn1Primitive] to null (i.e. verifies the tag to be [BERTags.NULL] and the content to be empty
 *
 * @throws Asn1Exception  on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readNull() = decode(NULL) {}

/**
 * Name seems odd, but this is just an exception-free version of [readNull]
 */
fun Asn1Primitive.readNullOrNull() = runCatching { readNull() }.getOrNull()


/**
 * Returns this [Asn1Tagged] children, if its tag matches [tag]
 *
 * @throws Asn1TagMismatchException if the tag does not match
 */
@Throws(Asn1TagMismatchException::class)
fun Asn1Tagged.verifyTag(tag: UByte): List<Asn1Element> {
    if (this.tag != tag.toExplicitTag()) throw Asn1TagMismatchException(tag.toExplicitTag(), this.tag)
    return this.children
}

/**
 * Exception-free version of [verifyTag]
 */
fun Asn1Tagged.verifyTagOrNull(tag: UByte) = runCatching { verifyTag(tag) }.getOrNull()


/**
 * Generic decoding function. Verifies that this [Asn1Primitive]'s tag matches [tag]
 * and transforms its content as per [transform]
 * @throws Asn1Exception all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
inline fun <reified T> Asn1Primitive.decode(tag: UByte, transform: (content: ByteArray) -> T) = runRethrowing {
    if (tag != this.tag) throw Asn1TagMismatchException(tag, this.tag)
    transform(content)
}

/**
 * Exception-free version of [decode]
 */
inline fun <reified T> Asn1Primitive.decodeOrNull(tag: UByte, transform: (content: ByteArray) -> T) =
    runCatching { decode(tag, transform) }.getOrNull()

@Throws(Asn1Exception::class)
private fun Instant.Companion.decodeUtcTimeFromDer(input: ByteArray): Instant = runRethrowing {
    val s = input.decodeToString()
    if (s.length != 13) throw IllegalArgumentException("Input too short: $input")
    val year = "${s[0]}${s[1]}".toInt()
    val century = if (year <= 49) "20" else "19" // RFC 5280 4.1.2.5 Validity
    val isoString = "$century${s[0]}${s[1]}" + // year
            "-${s[2]}${s[3]}" + // month
            "-${s[4]}${s[5]}" + // day
            "T${s[6]}${s[7]}" + // hour
            ":${s[8]}${s[9]}" + // minute
            ":${s[10]}${s[11]}" + // seconds
            "${s[12]}" // time offset
    return parse(isoString)
}

@Throws(Asn1Exception::class)
private fun Instant.Companion.decodeGeneralizedTimeFromDer(input: ByteArray): Instant = runRethrowing {
    val s = input.decodeToString()
    if (s.length != 15) throw IllegalArgumentException("Input too short: $input")
    val isoString = "${s[0]}${s[1]}${s[2]}${s[3]}" + // year
            "-${s[4]}${s[5]}" + // month
            "-${s[6]}${s[7]}" + // day
            "T${s[8]}${s[9]}" + // hour
            ":${s[10]}${s[11]}" + // minute
            ":${s[12]}${s[13]}" + // seconds
            "${s[14]}" // time offset
    return parse(isoString)
}

/**
 * @throws Asn1Exception if the byte array is too long to be parsed to an int (note that only rudimentary checking happens)
 */
@Throws(Asn1Exception::class)
fun Int.Companion.decodeFromDer(input: ByteArray): Int = runRethrowing {
    if (input.size > 5) throw IllegalArgumentException("Absolute value too large!")
    return Long.decodeFromDer(input).toInt()
}

/**
 * @throws IllegalArgumentException if the byte array is too long to be parsed to a long (note that only rudimentary checking happens)
 */
@Throws(Asn1Exception::class)
fun Long.Companion.decodeFromDer(bytes: ByteArray): Long = runRethrowing {
    val input = if (bytes.size == 8) bytes else {
        if (bytes.size > 9) throw IllegalArgumentException("Absolute value too large!")
        val padding = if (bytes.first() and 0x80.toByte() != 0.toByte()) 0xFF.toByte() else 0x00.toByte()
        ByteArray(9 - bytes.size) { padding } + bytes
    }
    var result = 0L
    for (i in input.indices) {
        result = (result shl Byte.SIZE_BITS) or (input[i].toUByte().toLong())
    }
    return result
}


@Throws(Asn1Exception::class)
private fun ByteArray.readTlv(): TLV = runRethrowing {
    if (this.isEmpty()) throw IllegalArgumentException("Can't read TLV, input empty")
    val tag = this[0].toUByte()
    if (this.size == 1) return TLV(tag, byteArrayOf())
    val firstLength = this[1]
    if (firstLength == 0x82.toByte()) {
        if (this.size < 4) throw IllegalArgumentException("Can't decode length")
        val length = (this[2].toUByte().toInt() shl 8) + this[3].toUByte().toInt()
        if (this.size < 4 + length) throw IllegalArgumentException("Out of bytes")
        val value = this.drop(4).take(length).toByteArray()
        return TLV(tag, value)
    }
    if (firstLength == 0x81.toByte()) {
        if (this.size < 3) throw IllegalArgumentException("Can't decode length")
        val length = this[2].toUByte().toInt()
        if (this.size < 3 + length) throw IllegalArgumentException("Out of bytes")
        val value = this.drop(3).take(length).toByteArray()
        return TLV(tag, value)
    }
    val length = firstLength.toUByte().toInt()
    if (this.size < 2 + length)
        throw IllegalArgumentException("Out of bytes")
    val value = this.drop(2).take(length).toByteArray()
    return TLV(tag, value)
}

