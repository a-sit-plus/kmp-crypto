package at.asitplus.crypto.datatypes.cose

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.failure
import at.asitplus.KmmResult.Companion.success
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.asn1.encodeToByteArray
import at.asitplus.crypto.datatypes.cose.io.cborSerializer
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ArraySerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.SerialLabel
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure

/**
 * COSE public key as per [RFC 8152](https://www.rfc-editor.org/rfc/rfc8152.html#page-33).  Since this is used as part of a COSE-specific DTO, every property is nullable
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable(with = CoseKeySerializer::class)
data class CoseKey(
    val type: CoseKeyType,
    val keyId: ByteArray? = null,
    val algorithm: CoseAlgorithm? = null,
    val operations: Array<CoseKeyOperation>? = null,
    val baseIv: ByteArray? = null,
    val keyParams: CoseKeyParams?
) {
    override fun toString(): String {
        return "CoseKey(type=$type," +
                " keyId=${keyId?.encodeToString(Base16(strict = true))}," +
                " algorithm=$algorithm," +
                " operations=${operations?.contentToString()}," +
                " baseIv=${baseIv?.encodeToString(Base16(strict = true))}," +
                keyParams.toString()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseKey

        if (type != other.type) return false
        if (keyId != null) {
            if (other.keyId == null) return false
            if (!keyId.contentEquals(other.keyId)) return false
        } else if (other.keyId != null) return false
        if (algorithm != other.algorithm) return false
        if (operations != null) {
            if (other.operations == null) return false
            if (!operations.contentEquals(other.operations)) return false
        } else if (other.operations != null) return false
        if (baseIv != null) {
            if (other.baseIv == null) return false
            if (!baseIv.contentEquals(other.baseIv)) return false
        } else if (other.baseIv != null) return false
        if (keyParams != other.keyParams) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + (keyId?.contentHashCode() ?: 0)
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + (operations?.contentHashCode() ?: 0)
        result = 31 * result + (baseIv?.contentHashCode() ?: 0)
        result = 31 * result + keyParams.hashCode()
        return result
    }

    /**
     * @return a KmmResult wrapped [CryptoPublicKey] equivalent if conversion is possible (i.e. if all key params are set)
     * or the first error. More details in either [CoseKeyParams.RsaParams.toCryptoPublicKey] or [CoseKeyParams.EcYByteArrayParams.toCryptoPublicKey]
     */
    fun toCryptoPublicKey(): KmmResult<CryptoPublicKey> =
        keyParams?.toCryptoPublicKey() ?: failure(IllegalArgumentException("No public key parameters!"))

    fun serialize() = cborSerializer.encodeToByteArray(this)

    /**
     * Contains convenience functions
     */
    companion object {
        fun deserialize(it: ByteArray) =
            runCatching { cborSerializer.decodeFromByteArray<CoseKey>(it) }.wrap()

        fun fromKeyId(keyId: String): KmmResult<CoseKey> =
            runCatching { CryptoPublicKey.fromDid(keyId).toCoseKey().getOrThrow() }.wrap()

        fun fromIosEncoded(bytes: ByteArray): KmmResult<CoseKey> =
            runCatching { CryptoPublicKey.fromIosEncoded(bytes).toCoseKey().getOrThrow() }.wrap()

        fun fromCoordinates(curve: CoseEllipticCurve, x: ByteArray, y: ByteArray): KmmResult<CoseKey> =
            runCatching { CryptoPublicKey.Ec.fromCoordinates(curve.toJwkCurve(), x, y).toCoseKey().getOrThrow() }.wrap()

        @Deprecated("Use [fromIosEncoded] instead!")
        fun fromAnsiX963Bytes(type: CoseKeyType, curve: CoseEllipticCurve, it: ByteArray) =
            if (type == CoseKeyType.EC2 && curve == CoseEllipticCurve.P256) {
                val pubKey = CryptoPublicKey.Ec.fromAnsiX963Bytes(it)
                pubKey.toCoseKey()
            } else KmmResult.failure(UnsupportedOperationException("Key type $type not supported"))


        @Throws(Throwable::class)
        @Deprecated("Use [fromIosEncoded] instead")
        fun fromCoordinates(
            type: CoseKeyType,
            curve: CoseEllipticCurve,
            x: ByteArray,
            y: ByteArray
        ): CoseKey? = CryptoPublicKey.Ec.fromCoordinates(curve.toJwkCurve(), x, y).toCoseKey().getOrNull()

    }
}

/**
 * Converts [CryptoPublicKey] into a KmmResult wrapped [CoseKey]
 * If [algorithm] is not set then key can be used for any algorithm with same kty (RFC 8152), returns [IllegalArgumentException] for invalid kty/algorithm pairs
 */
fun CryptoPublicKey.toCoseKey(algorithm: CoseAlgorithm? = null): KmmResult<CoseKey> =
    when (this) {
        is CryptoPublicKey.Ec ->
            if ((algorithm != null) && (algorithm != when (curve) {
                    EcCurve.SECP_256_R_1 -> CoseAlgorithm.ES256
                    EcCurve.SECP_384_R_1 -> CoseAlgorithm.ES384
                    EcCurve.SECP_521_R_1 -> CoseAlgorithm.ES512
                })
            ) failure(IllegalArgumentException("Algorithm and Key Type mismatch"))
            else success(
                CoseKey(
                    keyParams = CoseKeyParams.EcYByteArrayParams(
                        curve = curve.toCoseCurve(),
                        x = x,
                        y = y
                    ),
                    type = CoseKeyType.EC2,
                    keyId = didEncoded.encodeToByteArray(),
                    algorithm = algorithm
                )
            )

        is CryptoPublicKey.Rsa ->
            if ((algorithm != null) && (algorithm !in listOf(
                    CoseAlgorithm.PS256, CoseAlgorithm.PS384, CoseAlgorithm.PS512,
                    CoseAlgorithm.RS256, CoseAlgorithm.RS384, CoseAlgorithm.RS512
                ))
            ) failure(IllegalArgumentException("Algorithm and Key Type mismatch"))
            else success(
                CoseKey(
                    keyParams = CoseKeyParams.RsaParams(
                        n = n,
                        e = e.encodeToByteArray()
                    ),
                    type = CoseKeyType.RSA,
                    keyId = didEncoded.encodeToByteArray(),
                    algorithm = algorithm
                )
            )
    }

private const val COSE_KID = "coseKid"
var CryptoPublicKey.coseKid: String
    get() = additionalProperties[COSE_KID] ?: didEncoded
    set(value) {
        additionalProperties[COSE_KID] = value
    }


@OptIn(ExperimentalSerializationApi::class)
object CoseKeySerializer : KSerializer<CoseKey> {

    @Serializable
    private class CoseKeySerialContainer(
        @SerialLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @SerialLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @SerialLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @SerialLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @SerialLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @SerialLabel(-1)
        @SerialName("crv")
        val curve: CoseEllipticCurve? = null,
        @SerialLabel(-2)
        @SerialName("x")
        @ByteString
        val x: ByteArray? = null,
        @SerialLabel(-3)
        @SerialName("y")
        @ByteString
        val y: ByteArray? = null,
        @SerialLabel(-1)
        @SerialName("n")
        val n: ByteArray? = null,
        @SerialLabel(-2)
        @SerialName("e")
        @ByteString
        val e: ByteArray? = null,
        @SerialLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null,
        @SerialLabel(-1)
        @SerialName("k")
        @ByteString
        val k: ByteArray? = null
    ) {
        constructor(src: CoseKey) : this(
            src.type,
            src.keyId,
            src.algorithm,
            src.operations,
            src.baseIv,
            if (src.keyParams is CoseKeyParams.EcYByteArrayParams) src.keyParams.curve else null,
            if (src.keyParams is CoseKeyParams.EcYByteArrayParams) src.keyParams.x else null,
            if (src.keyParams is CoseKeyParams.EcYByteArrayParams) src.keyParams.y else null,
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.n
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.e
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.SymmKeyParams -> params.k
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.d
                is CoseKeyParams.EcYByteArrayParams -> params.d
                else -> null
            },

            )
    }

    private interface SerialContainer {
        fun toCoseKey(): CoseKey
    }


    @Serializable
    private class CoseEcKeySerialContainer(
        @SerialLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @SerialLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @SerialLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @SerialLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @SerialLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @SerialLabel(-1)
        @SerialName("crv")
        val curve: CoseEllipticCurve? = null,
        @SerialLabel(-2)
        @SerialName("x")
        @ByteString
        val x: ByteArray? = null,
        @SerialLabel(-3)
        @SerialName("y")
        @ByteString
        val y: ByteArray? = null,
        @SerialLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null
    ) : SerialContainer {
        init {
            if (type != CoseKeyType.EC2) throw IllegalArgumentException("Not an EC key!")
        }

        override fun toCoseKey() =
            CoseKey(type, keyId, algorithm, operations, baseIv, CoseKeyParams.EcYByteArrayParams(curve, x, y, d))

    }


    @Serializable
    private class CoseRsaKeySerialContainer(
        @SerialLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @SerialLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @SerialLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @SerialLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @SerialLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @SerialLabel(-1)
        @SerialName("n")
        val n: ByteArray? = null,
        @SerialLabel(-2)
        @SerialName("e")
        @ByteString
        val e: ByteArray? = null,
        @SerialLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null
    ) : SerialContainer {
        init {
            if (type != CoseKeyType.RSA) throw IllegalArgumentException("Not an RSA key!")
        }

        override fun toCoseKey() = CoseKey(type, keyId, algorithm, operations, baseIv, CoseKeyParams.RsaParams(n, e, d))
    }

    @Serializable
    private class CoseSymmKeySerialContainer(
        @SerialLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @SerialLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @SerialLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @SerialLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @SerialLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @SerialLabel(-1)
        @SerialName("k")
        val k: ByteArray? = null,
    ) : SerialContainer {
        init {
            if (type != CoseKeyType.SYMMETRIC) throw IllegalArgumentException("Not a symmetric key!")
            if (k == null) throw IllegalArgumentException("Parameter k not optional for symmetric keys")
        }

        override fun toCoseKey() =
            CoseKey(type, keyId, algorithm, operations, baseIv, CoseKeyParams.SymmKeyParams(k!!))

    }

    override val descriptor: SerialDescriptor
        get() = CoseKeySerialContainer.serializer().descriptor

    override fun deserialize(decoder: Decoder): CoseKey {
        val labels = mapOf<String, Long>(
            "kty" to 1,
            "kid" to 2,
            "alg" to 3,
            "key_ops" to 4,
            "Base IV" to 5,
            "k/n/crv" to -1,
            "x/e" to -2,
            "y" to -3,
            "d" to 4
        )

        lateinit var type: CoseKeyType
        var keyId: ByteArray? = null
        var alg: CoseAlgorithm? = null
        var keyOps: Array<CoseKeyOperation>? = null
        var baseIv: ByteArray? = null
        var n: ByteArray? = null
        var crv: CoseEllipticCurve? = null
        var xOrE: ByteArray? = null
        var y: ByteArray? = null
        var d: ByteArray? = null
        var k: ByteArray? = null

        decoder.decodeStructure(descriptor) {
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == -1) break
                val label = descriptor.getElementAnnotations(index).filterIsInstance<SerialLabel>().first().label
                when (label) {
                    labels["kty"] -> type =
                        decodeSerializableElement(CoseKeyTypeSerializer.descriptor, index, CoseKeyTypeSerializer)

                    labels["kid"] -> keyId =
                        decodeNullableSerializableElement(
                            ByteArraySerializer().descriptor,
                            index,
                            ByteArraySerializer()
                        )

                    labels["alg"] -> alg =
                        decodeNullableSerializableElement(
                            CoseAlgorithmSerializer.descriptor,
                            index,
                            CoseAlgorithmSerializer
                        )

                    labels["key_ops"] -> keyOps =
                        decodeNullableSerializableElement(
                            ArraySerializer(CoseKeyOperationSerializer).descriptor,
                            index,
                            ArraySerializer(CoseKeyOperationSerializer)
                        )

                    labels["k/n/crv"] -> {
                        when (type) {
                            CoseKeyType.EC2 -> {
                                val deser = CoseEllipticCurveSerializer
                                crv = decodeNullableSerializableElement(deser.descriptor, index, deser)
                            }

                            CoseKeyType.RSA -> {
                                val deser = ByteArraySerializer()
                                n = decodeNullableSerializableElement(deser.descriptor, index, deser)
                            }

                            CoseKeyType.SYMMETRIC -> {
                                val deser = ByteArraySerializer()
                                k = decodeNullableSerializableElement(deser.descriptor, index, deser)
                            }
                        }

                    }

                    labels["x/e"] -> xOrE =
                        decodeNullableSerializableElement(
                            ByteArraySerializer().descriptor,
                            index,
                            ByteArraySerializer()
                        )

                    labels["y"] -> y =
                        decodeNullableSerializableElement(
                            ByteArraySerializer().descriptor,
                            index,
                            ByteArraySerializer()
                        )

                    labels["d"] -> d =
                        decodeNullableSerializableElement(
                            ByteArraySerializer().descriptor,
                            index,
                            ByteArraySerializer()
                        )

                    else -> {
                        break
                    }
                }
            }
        }
        return when (type) {
            CoseKeyType.EC2 -> {
                CoseEcKeySerialContainer(type, keyId, alg, keyOps, baseIv, crv, xOrE, y, d).toCoseKey()
            }

            CoseKeyType.RSA -> {
                CoseRsaKeySerialContainer(type, keyId, alg, keyOps, baseIv, n, xOrE, d).toCoseKey()
            }

            CoseKeyType.SYMMETRIC -> {
                CoseSymmKeySerialContainer(type,keyId,alg,keyOps,baseIv, k).toCoseKey()
            }
        }
    }

    override fun serialize(encoder: Encoder, value: CoseKey) {
        encoder.encodeSerializableValue(CoseKeySerialContainer.serializer(), CoseKeySerialContainer(value))
    }

}