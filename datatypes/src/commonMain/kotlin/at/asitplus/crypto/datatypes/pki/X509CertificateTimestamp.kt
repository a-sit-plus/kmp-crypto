package at.asitplus.crypto.datatypes.pki

import at.asitplus.crypto.datatypes.asn1.*
import kotlinx.datetime.Instant
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

//TODO everything here feels off! Why isn't this an Encodable and why is his companion not implementing Asn1Decodable???
@Serializable(with = CertTimeStampSerializer::class)
class CertificateTimeStamp(val asn1Object: Asn1Primitive) {
    init {
        if (asn1Object.tag != BERTags.UTC_TIME && asn1Object.tag != BERTags.GENERALIZED_TIME)
            throw IllegalArgumentException("Not a timestamp!")
    }

    constructor(instant: Instant) : this(instant.wrap())

    val instant by lazy { asn1Object.readInstant() }

    companion object {
        fun Instant.wrap() = if (this > Instant.parse("2050-01-01T00:00:00Z")) { // per RFC 5280 4.1.2.5
            Asn1Primitive(BERTags.GENERALIZED_TIME, encodeToAsn1GeneralizedTime())
        } else {
            Asn1Primitive(BERTags.UTC_TIME, encodeToAsn1UtcTime())
        }

    }
}

object CertTimeStampSerializer : KSerializer<CertificateTimeStamp> {
    override val descriptor = PrimitiveSerialDescriptor("CertificateTimestamp", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder) =
        CertificateTimeStamp(Asn1Element.decodeFromDerHexString(decoder.decodeString()) as Asn1Primitive)

    override fun serialize(encoder: Encoder, value: CertificateTimeStamp) {
        encoder.encodeString(value.asn1Object.toDerHexString())
    }

}