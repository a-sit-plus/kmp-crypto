package at.asitplus.crypto.datatypes.jws

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Supported JWE algorithms.
 *
 * See [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)
 * and also [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)
 */
@Serializable(with = JweEncryptionSerializer::class)
enum class JweEncryption(val text: String) {

    A128GCM("A128GCM"),
    A192GCM("A192GCM"),
    A256GCM("A256GCM");

    val encryptionKeyLength
        get() = when (this) {
            A128GCM -> 128
            A192GCM -> 192
            A256GCM -> 256
        }

    val ivLengthBits
        get() = when (this) {
            A128GCM -> 128
            A192GCM -> 192
            A256GCM -> 128
        }
}

object JweEncryptionSerializer : KSerializer<JweEncryption?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JweEncryptionSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JweEncryption?) {
        value?.let { encoder.encodeString(it.text) }
    }

    override fun deserialize(decoder: Decoder): JweEncryption? {
        val decoded = decoder.decodeString()
        return JweEncryption.entries.firstOrNull { it.text == decoded }
    }
}

