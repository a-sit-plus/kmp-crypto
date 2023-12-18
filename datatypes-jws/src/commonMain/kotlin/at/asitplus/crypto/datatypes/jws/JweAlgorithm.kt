package at.asitplus.crypto.datatypes.jws

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = JweAlgorithmSerializer::class)
enum class JweAlgorithm(val text: String) {
    ECDH_ES("ECDH-ES"),
    RSA_OAEP_256("RSA-OAEP-256"),
    RSA_OAEP_384("RSA-OAEP-384"),
    RSA_OAEP_512("RSA-OAEP-512")
}

object JweAlgorithmSerializer : KSerializer<JweAlgorithm?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JweAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JweAlgorithm?) {
        value?.let { encoder.encodeString(it.text) }
    }

    override fun deserialize(decoder: Decoder): JweAlgorithm? {
        val decoded = decoder.decodeString()
        return JweAlgorithm.entries.firstOrNull { it.text == decoded }
    }

}