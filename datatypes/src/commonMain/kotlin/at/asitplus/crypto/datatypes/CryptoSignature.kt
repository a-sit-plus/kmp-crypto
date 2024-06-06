package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.asn1.BERTags.BIT_STRING
import at.asitplus.crypto.datatypes.asn1.DERTags.DER_SEQUENCE
import at.asitplus.crypto.datatypes.io.Base64Strict
import at.asitplus.crypto.datatypes.misc.BitLength
import at.asitplus.crypto.datatypes.misc.max
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
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
        return "${this::class.simpleName ?: "CryptoSignature"}(signature=${signature.prettyPrint()})"
    }

    object CryptoSignatureSerializer : KSerializer<CryptoSignature> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor("CryptoSignature", PrimitiveKind.STRING)

        override fun deserialize(decoder: Decoder): CryptoSignature {
            return CryptoSignature.decodeFromDer(decoder.decodeString().decodeToByteArray(Base64Strict))
        }

        override fun serialize(encoder: Encoder, value: CryptoSignature) {
            encoder.encodeString(value.encodeToDer().encodeToString(Base64Strict))
        }
    }


    sealed class EC private constructor (
        /** r - ECDSA signature component */
        val r: BigInteger,
        /** s - ECDSA signature component */
        val s: BigInteger)
        : CryptoSignature(Asn1.Sequence { +r.encodeToTlv(); +s.encodeToTlv() })
    {

        init {
            require(r.isPositive) { "r must be positive" }
            require(s.isPositive) { "s must be positive" }
        }

        override fun encodeToTlvBitString(): Asn1Element = encodeToDer().encodeToTlvBitString()

        /**
         * Two signatures are considered equal if `r` and `s` are equal.
         * This is true even if they are of definite length, and the lengths differ.
         *
         * We chose this approach to allow definite and indefinite length encodings of the same signature
         * to be equal, while preserving the transitivity contract of `equals`.
         */
        override fun equals(other: Any?): Boolean {
            if (other !is CryptoSignature.EC) return false
            return ((this.s == other.s) && (this.r == other.r))
        }

        /** @see equals */
        override fun hashCode() = 31 * this.s.hashCode() + this.r.hashCode()

        class IndefiniteLength internal constructor(
            r: BigInteger, s:BigInteger
        ) : EC(r,s) {
            override val rawByteArray get() =
                throw IllegalStateException("Cannot convert indefinite length signature to raw bytes")

            /**
             * specifies the curve's scalar byte length for this signature, allowing it to be converted to raw bytes
             */
            fun withScalarByteLength(l: UInt) =
                EC.DefiniteLength(l, r, s)

            /**
             * specifies the curve context for this signature, allowing it to be converted to raw bytes
             */
            fun withCurve(c: ECCurve) =
                withScalarByteLength(c.scalarLength.bytes)

            /**
             * tries to guess the curve from the bit length of the indefinite-length r/s values
             * this will work well in the vast majority of cases, but may fail in pathological edge cases
             * (when r/s have a very large number of leading zeroes)
             */
            fun guessCurve(): EC.DefiniteLength {
                val minLength = max(BitLength.of(r), BitLength.of(s))
                val idx = curvesByScalarLength.binarySearchBy(minLength) { it.scalarLength }

                return withCurve(
                    when {
                        idx >= 0 -> curvesByScalarLength[idx]
                        idx >= -curvesByScalarLength.size -> curvesByScalarLength[-1-idx]
                        else -> throw IllegalArgumentException("No curve with bit length >= $minLength is supported")
                    }
                )
            }

            companion object {
                private val curvesByScalarLength by lazy { ECCurve.entries.sortedBy { it.scalarLength } }
            }
        }

        class DefiniteLength internal constructor (
            /**
             * scalar byte length of the underlying curve;
             * we do not know _which_ curve with this particular byte length
             * since raw signatures do not carry this information
             */
            val scalarByteLength: UInt,
            r: BigInteger, s: BigInteger
        ) : EC(r,s) {
            init {
                val max = scalarByteLength.toInt()*8

                require(r.bitLength() <= max) {
                    "r is ${r.bitLength()} bits long, expected at most ${scalarByteLength.toInt()} bytes (${max} bits)"}

                require(s.bitLength() <= scalarByteLength.toInt()*8) {
                    "s is ${s.bitLength()} bits long, expected at most ${scalarByteLength.toInt()} bytes (${max} bits)"}
            }
            /**
             * Concatenates [r] and [s], padding each one to the next largest coordinate length
             * of an [ECCurve], for use in e.g. JWS signatures.
             */
            override val rawByteArray by lazy {
                r.toByteArray().ensureSize(scalarByteLength) +
                        s.toByteArray().ensureSize(scalarByteLength)
            }
        }

        companion object : Asn1Decodable<Asn1Element, EC.IndefiniteLength> {

            fun fromRS(r: BigInteger, s: BigInteger) =
                EC.IndefiniteLength(r,s)

            /** load CryptoSignature from raw byte array (r and s concatenated) */
            fun fromRawBytes(input: ByteArray): EC.DefiniteLength {
                require(input.size.rem(2) == 0) { "Raw signature has odd number of bytes" }
                val sz = input.size.div(2)
                return EC.DefiniteLength(sz.toUInt(),
                    r = BigInteger.fromByteArray(input.copyOfRange(0, sz), Sign.POSITIVE),
                    s = BigInteger.fromByteArray(input.copyOfRange(sz, 2*sz), Sign.POSITIVE))
            }

            /** load from raw byte array (r and s concatenated), asserting that the size fits this particular curve */
            @Throws(IllegalArgumentException::class)
            fun fromRawBytes(curve: ECCurve, input: ByteArray): EC.DefiniteLength {
                val sz = curve.scalarLength.bytes.toInt()
                require(input.size == sz * 2)
                return fromRawBytes(input)
            }

            @Throws(Asn1Exception::class)
            fun decodeFromTlvBitString(src: Asn1Primitive): EC.IndefiniteLength = runRethrowing {
                decodeFromDer(src.readBitString().rawBytes)
            }

            override fun decodeFromTlv(src: Asn1Element): EC.IndefiniteLength {
                src as Asn1Sequence
                val r = (src.nextChild() as Asn1Primitive).readBigInteger()
                val s = (src.nextChild() as Asn1Primitive).readBigInteger()
                if (src.hasMoreChildren()) throw IllegalArgumentException("Illegal Signature Format")
                return fromRS(r,s)
            }

            @Deprecated("use fromRawBytes", ReplaceWith("CryptoSignature.EC.fromRawBytes(input)"))
            operator fun invoke(input: ByteArray): DefiniteLength = fromRawBytes(input)
        }

    }

    class RSAorHMAC(input: ByteArray) : CryptoSignature(
        Asn1Primitive(BIT_STRING, input)
    ) {
        override val rawByteArray by lazy { (signature as Asn1Primitive).decode(BIT_STRING) { it } }
        override fun encodeToTlvBitString(): Asn1Element = this.encodeToTlv()

        companion object {
            @Throws(Asn1Exception::class)
            fun decodeFromTlvBitString(src: Asn1Primitive): RSAorHMAC = runRethrowing {
                decodeFromTlv(src) as RSAorHMAC
            }
        }
    }

    companion object : Asn1Decodable<Asn1Element, CryptoSignature> {
        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Element): CryptoSignature = runRethrowing {
            when (src.tag) {
                BIT_STRING -> RSAorHMAC((src as Asn1Primitive).decode(BIT_STRING) { it })
                DER_SEQUENCE -> EC.decodeFromTlv(src as Asn1Sequence)

                else -> throw IllegalArgumentException("Unknown Signature Format")
            }
        }
    }
}
