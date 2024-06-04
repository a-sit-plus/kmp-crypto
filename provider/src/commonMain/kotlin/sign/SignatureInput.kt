package at.asitplus.crypto.provider.sign

import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.misc.BitLength
import org.kotlincrypto.hash.sha2.SHA256
import org.kotlincrypto.hash.sha2.SHA384
import org.kotlincrypto.hash.sha2.SHA512

class SignatureInput private constructor (
    val data: Sequence<ByteArray>,
    val format: Format
){

    enum class Format {
        RAW_BYTES,
        SHA_256,
        SHA_384,
        SHA_512;

        val fixedLength: BitLength? get() = when(this) {
            RAW_BYTES -> null
            SHA_256 -> 256u
            SHA_384 -> 384u
            SHA_512 -> 512u
        }?.let(::BitLength)

        fun canConvertTo(new: Format): Boolean = when (this) {
            RAW_BYTES -> true
            else -> (this == new)
        }

        fun convertTo(other: Format, data: Sequence<ByteArray>): Sequence<ByteArray> {
            if (this == other) return data
            require(canConvertTo(other))
            return when (other) {
                RAW_BYTES -> data
                SHA_256 -> sequenceOf(SHA256().let { data.forEach(it::update); it.digest() })
                SHA_384 -> sequenceOf(SHA384().let { data.forEach(it::update); it.digest() })
                SHA_512 -> sequenceOf(SHA512().let { data.forEach(it::update); it.digest() })
            }
        }
    }

    companion object {
        /** only use this if you know what you are doing */
        fun unsafeCreate(data: ByteArray, format: Format): SignatureInput {
            format.fixedLength?.let { require(data.size == it.bytes.toInt()) }
            return SignatureInput(sequenceOf(data), format)
        }
    }

    fun convertTo(format: Format): SignatureInput {
        if (this.format == format) return this
        return SignatureInput(this.format.convertTo(format, this.data), format)
    }

    constructor(data: ByteArray) : this(sequenceOf(data), Format.RAW_BYTES)
    constructor(data: Sequence<ByteArray>): this(data, Format.RAW_BYTES)
}