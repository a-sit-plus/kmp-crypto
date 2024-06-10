package at.asitplus.crypto.provider.sign

import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.asn1.ensureSize
import at.asitplus.crypto.datatypes.misc.BitLength
import at.asitplus.crypto.provider.hash.digest
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

typealias SignatureInputFormat = Digest?
internal val SignatureInputFormat.jcaAlgorithmComponent get() = when (this) {
    null -> "None"
    Digest.SHA1 -> "SHA1"
    Digest.SHA256 -> "SHA256"
    Digest.SHA384 -> "SHA384"
    Digest.SHA512 -> "SHA512"
}
private val RAW_BYTES: SignatureInputFormat = null
class SignatureInput private constructor (
    val data: Sequence<ByteArray>,
    val format: SignatureInputFormat
){

    companion object {
        /** only use this if you know what you are doing */
        fun unsafeCreate(data: ByteArray, format: SignatureInputFormat): SignatureInput {
            if (format != null)
                require(data.size == format.outputLength.bytes.toInt())

            return SignatureInput(sequenceOf(data), format)
        }
    }

    fun convertTo(format: SignatureInputFormat): SignatureInput {
        if (this.format == format) return this
        if (this.format != RAW_BYTES) throw IllegalStateException("Cannot convert from ${this.format} to $format")
        format!! /* RAW_BYTES is null; this is for the compiler */
        return SignatureInput(sequenceOf(format.digest(this.data)), format)
    }

    constructor(data: ByteArray) : this(sequenceOf(data), RAW_BYTES)
    constructor(data: Sequence<ByteArray>): this(data, RAW_BYTES)

    /**
     * Takes the leftmost bits of the byte array, and converts them to an unsigned `BigInteger`.
     *
     * (This matches the ECDSA spec.)
     */
    fun asBigInteger(length: BitLength): BigInteger {
        val target = length.bytes.toInt()
        val dataIt = data.iterator()
        var resultBytes = if(dataIt.hasNext()) dataIt.next() else byteArrayOf()
        while (resultBytes.size < target) {
            if (dataIt.hasNext()) resultBytes += dataIt.next().also { require(it.isNotEmpty()) }
            else break
        }
        if (resultBytes.size > target)
            resultBytes = resultBytes.copyOfRange(0, target)
        require(resultBytes.size <= target)

        return BigInteger.fromByteArray(resultBytes, Sign.POSITIVE).let {
            if ((resultBytes.size == target) && (length.bitSpacing != 0u))
                it.shr(length.bitSpacing.toInt())
            else
                it
        }
    }
}
