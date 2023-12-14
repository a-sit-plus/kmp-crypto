package at.asitplus.crypto.datatypes.jws

import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

/**
 * Representation of a signed JSON Web Signature object, i.e. consisting of header, payload and signature.
 *
 * See [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
 */
data class JwsSigned(
    val header: JwsHeader,
    val payload: ByteArray,
    val signature: CryptoSignature,
    val plainSignatureInput: String,
) {

    fun serialize(): String {
        return "${plainSignatureInput}.${signature.rawByteArray.encodeToString(Base64UrlStrict)}"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsSigned

        if (header != other.header) return false
        if (!payload.contentEquals(other.payload)) return false
        return signature == other.signature
    }

    override fun hashCode(): Int {
        var result = header.hashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + signature.hashCode()
        return result
    }

    companion object {
        fun parse(it: String): JwsSigned? {
            val stringList = it.replace("[^A-Za-z0-9-_.]".toRegex(), "").split(".")
            if (stringList.size != 3) return null.also { Napier.w("Could not parse JWS: $it") }
            val headerInput = stringList[0].decodeToByteArrayOrNull(Base64UrlStrict)
                ?: return null.also { Napier.w("Could not parse JWS: $it") }
            val header = JwsHeader.deserialize(headerInput.decodeToString())
                ?: return null.also { Napier.w("Could not parse JWS: $it") }
            val payload = stringList[1].decodeToByteArrayOrNull(Base64UrlStrict)
                ?: return null.also { Napier.w("Could not parse JWS: $it") }
            val signature = stringList[2].decodeToByteArrayOrNull(Base64UrlStrict)
                ?.let { it1 ->
                    when (header.algorithm) {
                        JwsAlgorithm.ES256, JwsAlgorithm.ES384, JwsAlgorithm.ES512 -> CryptoSignature.EC(it1)
                        else -> CryptoSignature.RSAorHMAC(it1)
                    }
                } ?: return null.also { Napier.w("Could not parse JWS: $it") }

            return JwsSigned(header, payload, signature, stringList[0] + "." + stringList[1])
        }


        fun prepareJwsSignatureInput(header: JwsHeader, payload: ByteArray): String =
            "${header.serialize().encodeToByteArray().encodeToString(Base64UrlStrict)}.${payload.encodeToString(Base64UrlStrict)}"
    }
}

