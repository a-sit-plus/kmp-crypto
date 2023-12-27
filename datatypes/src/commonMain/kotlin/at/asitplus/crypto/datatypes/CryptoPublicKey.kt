@file:OptIn(ExperimentalUnsignedTypes::class)

package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import at.asitplus.crypto.datatypes.io.MultibaseHelper
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * Representation of a public key structure
 */
@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
sealed class CryptoPublicKey : Asn1Encodable<Asn1Sequence>, Identifiable {

    /**
     * This is meant for storing additional properties, which may be relevant for certain use cases.
     * For example, Json Web Keys or Cose Keys may define an arbitrary key IDs.
     * This is not meant for Algorithm parameters! If an algorithm needs parameters, the implementing classes should be extended
     */
    //must be serializable, therefore <String,String>
    val additionalProperties = mutableMapOf<String, String>()

    /**
     * Representation of the key in DID format
     */
    @Transient
    abstract val didEncoded: String

    /**
     * Representation of this key in the same ways as iOS would encode it natively
     */
    @Transient
    abstract val iosEncoded: ByteArray

    override fun encodeToTlv() = when (this) {
        is Ec -> asn1Sequence {
            sequence {
                append(oid)
                append(curve.oid)
            }
            bitString(iosEncoded)
        }

        is Rsa -> {
            asn1Sequence {
                sequence {
                    append(oid)
                    asn1null()
                }
                bitString(iosEncoded)
            }
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, CryptoPublicKey> {


        /**
         * Parses a DID representation of a public key and
         * reconstructs the corresponding [CryptoPublicKey] from it
         * @throws Throwable all sorts of exception on invalid input
         */
        @Throws(Throwable::class)
        fun fromDid(input: String): CryptoPublicKey {
            val bytes = MultibaseHelper.stripDid(input)
            require(bytes.size > 3) { "Invalid key size" }
            require(bytes[0] == 0x12.toByte()) { "Unknown public key identifier" }

            return when (bytes[1]) {
                0x90.toByte(), 0x91.toByte(), 0x92.toByte() ->
                    Ec.fromAnsiX963Bytes(byteArrayOf(Ec.ANSI_PREFIX, *bytes.drop(2).toByteArray()))

                0x05.toByte() ->
                    Rsa.fromPKCS1encoded(bytes.drop(2).toByteArray())

                else ->
                    throw IllegalArgumentException("Unknown public key identifier")
            }
        }


        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence): CryptoPublicKey = runRethrowing {
            if (src.children.size != 2) throw Asn1StructuralException("Invalid SPKI Structure!")
            val keyInfo = src.nextChild() as Asn1Sequence
            if (keyInfo.children.size != 2) throw Asn1StructuralException("Superfluous data in  SPKI!")

            when (val oid = (keyInfo.nextChild() as Asn1Primitive).readOid()) {
                Ec.oid -> {
                    val curveOid = (keyInfo.nextChild() as Asn1Primitive).readOid()
                    val curve = EcCurve.entries.find { it.oid == curveOid }
                        ?: throw Asn1Exception("Curve not supported: $curveOid")

                    val bitString = (src.nextChild() as Asn1Primitive).readBitString()
                    if (bitString.rawBytes.first() != Ec.ANSI_PREFIX) throw Asn1Exception("EC key not prefixed with 0x04")
                    val xAndY = bitString.rawBytes.drop(1)
                    val coordLen = curve.coordinateLengthBytes.toInt()
                    val x = xAndY.take(coordLen).toByteArray()
                    val y = xAndY.drop(coordLen).take(coordLen).toByteArray()
                    return Ec.fromCoordinates(curve, x, y)
                }

                Rsa.oid -> {
                    (keyInfo.nextChild() as Asn1Primitive).readNull()
                    val bitString = (src.nextChild() as Asn1Primitive).readBitString()
                    val rsaSequence = Asn1Element.parse(bitString.rawBytes) as Asn1Sequence
                    val n = (rsaSequence.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
                    val e = (rsaSequence.nextChild() as Asn1Primitive).readInt()
                    if (rsaSequence.hasMoreChildren()) throw Asn1StructuralException("Superfluous data in SPKI!")
                    return Rsa(n, e)
                }

                else -> throw Asn1Exception("Unsupported Key Type: $oid")

            }
        }

        /**
         * Parses this key from an iOS-encoded one
         */
        @Throws(Throwable::class)
        fun fromIosEncoded(it: ByteArray): CryptoPublicKey =
            when (it[0].toUByte()) {
                Ec.ANSI_PREFIX.toUByte() -> Ec.fromAnsiX963Bytes(it)
                DERTags.DER_SEQUENCE -> Rsa.fromPKCS1encoded(it)
                else -> throw IllegalArgumentException("Unsupported Key type")
            }
    }

    /**
     * RSA Public key
     */
    @Serializable
    data class Rsa
    @Throws(IllegalArgumentException::class)
    private constructor(
        /**
         * RSA key size
         */
        val bits: Size,

        /**
         * modulus
         */
        @Serializable(with = ByteArrayBase64Serializer::class) val n: ByteArray,

        /**
         * public exponent
         */
        val e: Int,
    ) : CryptoPublicKey() {

        init {
            val computed = Size.of(n)
            if (bits != computed) throw IllegalArgumentException("Provided number of bits (${bits.number}) does not match computed number of bits (${computed.number})")
        }

        @Throws(IllegalArgumentException::class)
        private constructor(params: RsaParams) : this(
            params.size,
            params.n,
            params.e
        )

        /**
         * @throws IllegalArgumentException in case of illegal input (odd key size, for example)
         */
        @Throws(IllegalArgumentException::class)
        constructor(n: ByteArray, e: Int) : this(sanitizeRsaInputs(n, e))

        override val oid = Rsa.oid

        /**
         * enum of supported RSA key sized. For sanity checks!
         */
        enum class Size(val number: UInt) {
            RSA_512(512u),
            RSA_1024(1024u),
            RSA_2048(2048u),
            RSA_3027(3072u),
            RSA_4096(4096u);


            companion object : Identifiable {
                fun of(numBits: UInt) = entries.find { it.number == numBits }

                @Throws(IllegalArgumentException::class)
                fun of(n: ByteArray): Size {
                    val nTruncSize = n.dropWhile { it == 0.toByte() }.size
                    return entries.find { nTruncSize == (it.number.toInt() / 8) }
                        ?: throw IllegalArgumentException("Unsupported key size $nTruncSize")
                }

                override val oid = KnownOIDs.rsaEncryption
            }
        }

        @Transient
        override val didEncoded by lazy { MultibaseHelper.encodeToDid(this) }

        /**
         * PKCS#1 encoded RSA Public Key
         */
        @Transient
        override val iosEncoded by lazy {
            asn1Sequence {
                append(
                    Asn1Primitive(
                        BERTags.INTEGER,
                        n.ensureSize(bits.number / 8u)
                            .let { if (it.first() == 0x00.toByte()) it else byteArrayOf(0x00, *it) })
                )
                int(e)
            }.derEncoded
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null) return false
            if (this::class != other::class) return false

            other as Rsa

            return iosEncoded.contentEquals(other.iosEncoded)
        }

        override fun hashCode(): Int {
            var result = bits.hashCode()
            result = 31 * result + n.contentHashCode()
            result = 31 * result + e.hashCode()
            return result
        }

        companion object : Identifiable {
            /**
             * decodes a PKCS#1-encoded RSA key
             *
             * @throws Asn1Exception all sorts of exceptions on invalid input
             */
            @Throws(Asn1Exception::class)
            fun fromPKCS1encoded(input: ByteArray): Rsa = runRethrowing {
                val conv = Asn1Element.parse(input) as Asn1Sequence
                val n = (conv.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
                val e = (conv.nextChild() as Asn1Primitive).readInt()
                if (conv.hasMoreChildren()) throw Asn1StructuralException("Superfluous bytes")
                return Rsa(Size.of(n), n, e)
            }

            override val oid = KnownOIDs.rsaEncryption
        }
    }

    /**
     * EC public key representation
     * The properties and constructor params are exactly what their names suggest
     */
    @Serializable
    @SerialName("EC")
    data class Ec(
        val curve: EcCurve,
        @Serializable(with = ByteArrayBase64Serializer::class) val x: ByteArray,
        @Serializable(with = ByteArrayBase64Serializer::class) val y: ByteArray,
    ) : CryptoPublicKey() {

        override val oid = Ec.oid

        /**
         * ANSI X9.63 Encoding as used by iOS
         */
        @Transient
        override val iosEncoded by lazy {
            byteArrayOf(
                ANSI_PREFIX,
                *x.ensureSize(curve.coordinateLengthBytes),
                *y.ensureSize(curve.coordinateLengthBytes)
            )
        }

        @Transient
        override val didEncoded by lazy { MultibaseHelper.encodeToDid(this) }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as Ec

            if (curve != other.curve) return false
            if (!iosEncoded.contentEquals(other.iosEncoded)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = curve.hashCode()
            result = 31 * result + x.contentHashCode()
            result = 31 * result + y.contentHashCode()
            return result
        }

        companion object : Identifiable {

            const val ANSI_PREFIX = 0x04.toByte()

            /**
             * Decodes a key from the provided parameters
             */
            fun fromCoordinates(curve: EcCurve, x: ByteArray, y: ByteArray): Ec =
                Ec(curve = curve, x = x, y = y)

            /**
             * Decodes a key from its ANSI X9.63 representation
             */
            @Throws(Throwable::class)
            fun fromAnsiX963Bytes(src: ByteArray): CryptoPublicKey {
                if (src[0] != ANSI_PREFIX) throw IllegalArgumentException("No EC key")
                val curve = EcCurve.entries
                    .find { 2 * it.coordinateLengthBytes.toInt() == src.size - 1 }
                    ?: throw IllegalArgumentException("Unknown Curve")
                val numBytes = curve.coordinateLengthBytes.toInt()
                val x = src.drop(1).take(numBytes).toByteArray()
                val y = src.drop(1).drop(numBytes).take(numBytes).toByteArray()
                return Ec(curve = curve, x = x, y = y)
            }

            override val oid = KnownOIDs.ecPublicKey
        }
    }
}


//Helper typealias, for helper sanitization function. Enables passing all params along constructors for constructor chaining
private typealias RsaParams = Triple<ByteArray, Int, CryptoPublicKey.Rsa.Size>

private val RsaParams.n get() = first
private val RsaParams.e get() = second
private val RsaParams.size get() = third

/**
 * Sanitizes RSA parameters and maps it to the correct [CryptoPublicKey.Rsa.Size] enum
 * This function lives here and returns a typealiased Triple to allow for constructor chaining.
 * If we were to change the primary constructor, we'd need to write a custom serializer
 */
@Throws(IllegalArgumentException::class)
private fun sanitizeRsaInputs(n: ByteArray, e: Int): RsaParams = n.dropWhile { it == 0.toByte() }.toByteArray()
    .let { Triple(byteArrayOf(0, *it), e, CryptoPublicKey.Rsa.Size.of(it)) }