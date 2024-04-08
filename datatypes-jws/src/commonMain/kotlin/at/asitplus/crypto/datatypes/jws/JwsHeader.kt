@file:UseSerializers(ByteArrayBase64Serializer::class)

package at.asitplus.crypto.datatypes.jws

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.asn1.Asn1Element
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.parse
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import at.asitplus.crypto.datatypes.jws.io.jsonSerializer
import at.asitplus.crypto.datatypes.pki.X509Certificate
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.encodeToString

/**
 * Header of a [JwsSigned].
 *
 * See [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515#section-4)
 */
@Serializable
data class JwsHeader(
    @SerialName("kid")
    val keyId: String? = null,
    @SerialName("typ")
    val type: String? = null,
    @SerialName("alg")
    val algorithm: JwsAlgorithm,
    @SerialName("cty")
    val contentType: String? = null,
    @SerialName("x5c")
    val certificateChain: Array<ByteArray>? = null,
    @SerialName("nbf")
    @Serializable(with = InstantLongSerializer::class)
    val notBefore: Instant? = null,
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant? = null,
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant? = null,
    @SerialName("jwk")
    val jsonWebKey: JsonWebKey? = null,
    @SerialName("jku")
    val jsonWebKeySetUrl: String? = null,
    /**
     * OID4VP: Verifier Attestation JWT, used to authenticate a Verifier, by providing a JWT signed by a trusted
     * third party. May be parsed as a [JwsSigned], with [JsonWebToken] as the payload.
     */
    @SerialName("jwt")
    val attestationJwt: String? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    /**
     * Tries to compute a public key in descending order from [jsonWebKey], [keyId],
     * or [certificateChain], and takes the first success or null.
     */
    val publicKey: CryptoPublicKey? by lazy {
        jsonWebKey?.toCryptoPublicKey()?.getOrNull()
            ?: keyId?.let { runCatching { CryptoPublicKey.fromDid(it) } }?.getOrNull()
            ?: certificateChain
                ?.firstNotNullOfOrNull {
                    runCatching {
                        X509Certificate.decodeFromTlv(Asn1Element.parse(it) as Asn1Sequence).publicKey
                    }.getOrNull() ?: runCatching {
                        X509Certificate.decodeFromTlv(Asn1Element.parse(it.decodeX5c()) as Asn1Sequence).publicKey
                    }.getOrNull()
                }
    }

    private fun ByteArray.decodeX5c() = decodeToString()
        .replace("-----BEGIN CERTIFICATE-----\n", "")
        .replace("\n-----END CERTIFICATE-----", "")
        .decodeToByteArray(Base64())

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsHeader

        if (keyId != other.keyId) return false
        if (type != other.type) return false
        if (algorithm != other.algorithm) return false
        if (contentType != other.contentType) return false
        if (certificateChain != null) {
            if (other.certificateChain == null) return false
            if (!certificateChain.contentDeepEquals(other.certificateChain)) return false
        } else if (other.certificateChain != null) return false
        if (notBefore != other.notBefore) return false
        if (issuedAt != other.issuedAt) return false
        if (expiration != other.expiration) return false
        if (jsonWebKey != other.jsonWebKey) return false
        if (jsonWebKeySetUrl != other.jsonWebKeySetUrl) return false
        if (attestationJwt != other.attestationJwt) return false

        return true
    }

    override fun hashCode(): Int {
        var result = keyId?.hashCode() ?: 0
        result = 31 * result + (type?.hashCode() ?: 0)
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + (contentType?.hashCode() ?: 0)
        result = 31 * result + (certificateChain?.contentDeepHashCode() ?: 0)
        result = 31 * result + (notBefore?.hashCode() ?: 0)
        result = 31 * result + (issuedAt?.hashCode() ?: 0)
        result = 31 * result + (expiration?.hashCode() ?: 0)
        result = 31 * result + (jsonWebKey?.hashCode() ?: 0)
        result = 31 * result + (jsonWebKeySetUrl?.hashCode() ?: 0)
        result = 31 * result + (attestationJwt?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<JwsHeader>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }

    }
}