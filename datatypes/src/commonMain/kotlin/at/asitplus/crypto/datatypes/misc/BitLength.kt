package at.asitplus.crypto.datatypes.misc

import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlin.jvm.JvmInline

@JvmInline
value class BitLength (val bits: UInt): Comparable<BitLength> {
    /** how many bits are unused padding to get to the next full byte */
    inline val bitSpacing: UInt get() =
        bits.rem(8u).let { if (it != 0u) (8u-it) else 0u }

    inline val bytes: UInt get() =
        bits.floorDiv(8u) + (if(bits.rem(8u) != 0u) 1u else 0u)

    companion object {
        inline operator fun invoke(bits: Int) = BitLength(bits.toUInt())
        inline fun of(v: BigInteger) = BitLength(v.bitLength().toUInt())
    }

    inline override fun compareTo(other: BitLength): Int =
        bits.compareTo(other.bits)

}

inline fun min(a: BitLength, b: BitLength) =
    if (a.bits < b.bits) a else b

inline fun max(a: BitLength, b: BitLength) =
    if (a.bits < b.bits) b else a
