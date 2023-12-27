package at.asitplus.crypto.datatypes.io

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.base64.Base64ConfigBuilder
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Strict Base64 URL encode
 */
val Base64UrlStrict = Base64(config = Base64ConfigBuilder().apply {
    lineBreakInterval = 0
    encodeToUrlSafe = true
    isLenient = true
    padEncoded = false
}.build())


/**
 * Strict Base64 encoder
 */
val Base64Strict = Base64(config = Base64ConfigBuilder().apply {
    lineBreakInterval = 0
    encodeToUrlSafe = false
    isLenient = true
    padEncoded = true
}.build())


/**
 * De-/serializes Base64 strings to/from [ByteArray]
 */
object ByteArrayBase64Serializer : KSerializer<ByteArray> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteArrayBase64Serializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(value.encodeToString(Base64Strict))
    }

    //cannot be annotated with @Throws here because interfaces do not have annotations
    /**
     * @throws SerializationException on error
     */
    override fun deserialize(decoder: Decoder): ByteArray {
        return kotlin.runCatching { decoder.decodeString().decodeToByteArray(Base64Strict) }
            .getOrElse { throw SerializationException("Base64 decoding failed", it) }
    }

}


/**
 * De-/serializes Base64Url strings to/from [ByteArray]
 */
object ByteArrayBase64UrlSerializer : KSerializer<ByteArray> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteArrayBase64UrlSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(value.encodeToString(Base64UrlStrict))
    }

    //cannot be annotated with @Throws here because interfaces do not have annotations
    /**
     * @throws SerializationException on error
     */
    override fun deserialize(decoder: Decoder): ByteArray {
        return kotlin.runCatching { decoder.decodeString().decodeToByteArray(Base64UrlStrict) }
            .getOrElse { throw SerializationException("Base64 decoding failed", it) }
    }
}


object MultibaseHelper {
    private const val PREFIX_DID_KEY = "did:key"

    /**
     * https://datatracker.ietf.org/doc/html/draft-multiformats-multibase
     *
     * Adds correct Multibase identifier ('m') to Base64 encoding
     */
    private fun multibaseWrapBase64(it: ByteArray) = "m${it.encodeToString(Base64Strict)}"

    /**
     * Adds correct Multicodec identifier ('0x1205') to encoded RSA key
     */
    private fun multicodecWrapRSA(it: ByteArray) = byteArrayOf(0x12.toByte(), 0x05.toByte()) + it

    /**
     * Adds a Multicodec identifier ('0x129x') to encoded P-xxx key
     * We use 0x129x to identify uncompressed EC keys of their respective size. Currently only 0x120x are draft identifiers,
     * these however are used for compressed EC keys
     *
     *  0x1290 P-256
     *  0x1291 P-384
     *  0x1292 P-512
     */
    private fun multiCodecWrapEC(it: ByteArray, curve: EcCurve) =
        when(curve){
            EcCurve.SECP_256_R_1 -> byteArrayOf(0x12.toByte(), 0x90.toByte()) + it
            EcCurve.SECP_384_R_1 -> byteArrayOf(0x12.toByte(), 0x91.toByte()) + it
            EcCurve.SECP_521_R_1 -> byteArrayOf(0x12.toByte(), 0x92.toByte()) + it
        }

    /**
     * Returns something like `did:key:mEpA...` with the public key parameters appended in Base64.
     * This translates for example to `Base64(0x12, 0x90, EC-P-{256,384,521}-Key)`.
     */
    fun encodeToDid(key: CryptoPublicKey): String {
        return when (key) {
            is CryptoPublicKey.Ec -> "$PREFIX_DID_KEY:${
                multibaseWrapBase64(
                    multiCodecWrapEC(
                        key.iosEncoded.drop(1).toByteArray(),
                        key.curve
                    )
                )
            }"

            is CryptoPublicKey.Rsa -> "$PREFIX_DID_KEY:${
                multibaseWrapBase64(
                    multicodecWrapRSA(key.iosEncoded)
                )
            }"
        }
    }

    @Throws(Throwable::class)
    private fun multiKeyRemovePrefix(keyId: String): String =
        keyId.takeIf { it.startsWith("$PREFIX_DID_KEY:") }?.removePrefix("$PREFIX_DID_KEY:")
            ?: throw IllegalArgumentException("Key ID does not specify public key")

    @Throws(Throwable::class)
    private fun multibaseDecode(it: String): ByteArray =
        if (it.startsWith("m")) {
            it.removePrefix("m").decodeToByteArrayOrNull(Base64Strict)
                ?: throw SerializationException("Base64 decoding failed")
        } else throw IllegalArgumentException("Encoding not supported")

    @Throws(Throwable::class)
    internal fun stripDid(keyId: String): ByteArray = multibaseDecode(multiKeyRemovePrefix(keyId))
}