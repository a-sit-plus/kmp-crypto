package at.asitplus.crypto.datatypes.io

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString


/**
 * changjiashuai@gmail.com.
 *
 * Created by CJS on 2018/7/14.
 */
object BaseN {

    fun decode(alphabet: String, base: BigInteger, input: String): ByteArray {
        val bytes = decodeToBigInteger(alphabet, base, input).toByteArray()
        val stripSignByte = bytes.size > 1 && bytes[0].compareTo(0) == 0 && bytes[1] < 0
        var leadingZeros = 0
        var i = 0
        while (input[i] == alphabet[0]) {
            leadingZeros++
            i++
        }
        val tmp = ByteArray(bytes.size - (if (stripSignByte) 1 else 0) + leadingZeros)
        bytes.copyInto(
            tmp,
            startIndex = if (stripSignByte) 1 else 0,
            destinationOffset = leadingZeros,
            endIndex = tmp.size - leadingZeros - 1
        )
        return tmp
    }

    fun encode(alphabet: String, base: BigInteger, input: ByteArray): String {
        var bi = BigInteger.fromByteArray(input, Sign.POSITIVE)
        val sb = StringBuilder()
        while (bi >= base) {
            //求余
            val mod = bi.mod(base)
            sb.insert(0, alphabet[mod.intValue()])
            bi = bi.subtract(mod).divide(base)
        }
        sb.insert(0, alphabet[bi.intValue()])
        //convert leading zeros.
        for (b in input) {
            if (b.compareTo(0) == 0) {
                sb.insert(0, alphabet[0])
            } else {
                break
            }
        }
        return sb.toString()
    }

    fun decodeToBigInteger(alphabet: String, base: BigInteger, input: String): BigInteger {
        var bi = BigInteger.ZERO
        for (i in input.length - 1 downTo 0) {
            val alphaIndex = alphabet.indexOf(input[i])
            if (alphaIndex == -1) {
                throw IllegalStateException("Illegal character " + input[i] + " at " + i)
            }
            bi = bi.add(BigInteger.fromLong(alphaIndex.toLong()).multiply(base.pow(input.length - 1 - i)))
        }
        return bi
    }
}


/**
 * changjiashuai@gmail.com.
 *
 * Created by CJS on 2018/7/12.
 *
 * https://www.ietf.org/rfc/rfc4648.txt
 */
object MultiBase {

    enum class Base(val prefix: Char, val alphabet: String) {
        BASE2('0', "01"),
        BASE8('7', "01234567"),
        BASE10('9', "0123456789"),
        BASE16('f', "0123456789abcdef"),
        BASE16_UPPER('F', "0123456789ABCDEF"),
        BASE32('b', "abcdefghijklmnopqrstuvwxyz234567"),
        BASE32_UPPER('B', "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
        BASE32_PAD('c', "abcdefghijklmnopqrstuvwxyz234567="),
        BASE32_PAD_UPPER('C', "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="),
        BASE32_HEX('v', "0123456789abcdefghijklmnopqrstuvw"),
        BASE32_HEX_UPPER('V', "0123456789ABCDEFGHIJKLMNOPQRSTUVW"),
        BASE32_HEX_PAD('t', "0123456789abcdefghijklmnopqrstuvw="),
        BASE32_HEX_PAD_UPPER('T', "0123456789ABCDEFGHIJKLMNOPQRSTUVW="),
        BASE58_FLICKR('Z', "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"),
        BASE58_BTC('z', "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
        BASE64('m', "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
        BASE64_URL('u', "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"),
        BASE64_PAD('M', "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),
        BASE64_URL_PAD('U', "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=");

        companion object {

            private val baseMap = mutableMapOf<Char, Base>()

            init {
                for (base in entries) {
                    baseMap[base.prefix] = base
                }
            }

            fun lookup(prefix: Char): Base {
                return baseMap[prefix]
                    ?: throw IllegalStateException("Unknown Multibase type: $prefix")
            }
        }
    }


    fun encode(base: Base, data: ByteArray): String {
        return when (base) {
//            BASE2 -> base.prefix + String(BinaryCodec().encode(data))
//            BASE8 -> base.prefix + BaseN.encode(base.alphabet, BigInteger("8"), data)
//            BASE10 -> base.prefix + BaseN.encode(base.alphabet, BigInteger("10"), data)
            Base.BASE16 -> base.prefix + BaseN.encode(base.alphabet, BigInteger(16), data)
            Base.BASE16_UPPER -> base.prefix + BaseN.encode(base.alphabet, BigInteger(16), data)
            Base.BASE32 -> base.prefix + BaseN.encode(base.alphabet, BigInteger(32), data)
            Base.BASE32_UPPER -> base.prefix + BaseN.encode(base.alphabet, BigInteger(32), data)
            // Base.BASE32_PAD -> base.prefix + Base32().encodeToString(data).toLowerCase()
            Base.BASE32_PAD_UPPER -> base.prefix + BaseN.encode(base.alphabet, BigInteger(32), data)
            Base.BASE32_HEX -> base.prefix + BaseN.encode(base.alphabet, BigInteger(32), data)
            Base.BASE32_HEX_UPPER -> base.prefix + BaseN.encode(base.alphabet, BigInteger(32), data)
            //  Base.BASE32_HEX_PAD -> base.prefix + Base32(true).encodeToString(data).toLowerCase()
            //  Base.BASE32_HEX_PAD_UPPER -> base.prefix + Base32(true).encodeToString(data)
            Base.BASE58_FLICKR -> base.prefix + BaseN.encode(base.alphabet, BigInteger(58), data)
            Base.BASE58_BTC -> base.prefix + BaseN.encode(base.alphabet, BigInteger(58), data)
            Base.BASE64 -> base.prefix + BaseN.encode(base.alphabet, BigInteger(64), data)
            Base.BASE64_URL -> base.prefix + BaseN.encode(base.alphabet, BigInteger(64), data)
            Base.BASE64_PAD -> base.prefix + data.encodeToString(Base64Strict)
            Base.BASE64_URL_PAD -> base.prefix + data.encodeToString(Base64UrlStrict)
            else -> throw IllegalStateException("UnImplement multi type")
        }
    }

    fun decode(data: String): ByteArray {
        val prefix = data[0]
        val rest = data.substring(1)
        val base = Base.lookup(prefix)
        return when (base) {
//            BASE2 -> BinaryCodec().decode(rest.toByteArray())
//            BASE8 -> BaseN.decode(base.alphabet, BigInteger("8"), rest)
//            BASE10 -> BaseN.decode(base.alphabet, BigInteger("10"), rest)
            Base.BASE16 -> BaseN.decode(base.alphabet, BigInteger(16), rest)
            Base.BASE16_UPPER -> BaseN.decode(base.alphabet, BigInteger(16), rest)
            Base.BASE32 -> BaseN.decode(base.alphabet, BigInteger(32), rest)
            Base.BASE32_UPPER -> BaseN.decode(base.alphabet, BigInteger(32), rest)
            Base.BASE32_PAD_UPPER -> BaseN.decode(base.alphabet, BigInteger(32), rest)
            Base.BASE32_HEX -> BaseN.decode(base.alphabet, BigInteger(32), rest)
            Base.BASE32_HEX_UPPER -> BaseN.decode(base.alphabet, BigInteger(32), rest)
            Base.BASE58_FLICKR -> BaseN.decode(base.alphabet, BigInteger(58), rest)
            Base.BASE58_BTC -> BaseN.decode(base.alphabet, BigInteger(58), rest)
            Base.BASE64 -> BaseN.decode(base.alphabet, BigInteger(64), rest)
            Base.BASE64_URL -> BaseN.decode(base.alphabet, BigInteger(64), rest)
            Base.BASE64_PAD -> rest.decodeToByteArray(Base64Strict)
            Base.BASE64_URL_PAD -> rest.decodeToByteArray(Base64UrlStrict)
            else -> throw IllegalStateException("UnImplement multi type")
        }
    }
}