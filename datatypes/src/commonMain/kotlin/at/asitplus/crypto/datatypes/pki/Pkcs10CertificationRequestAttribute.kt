package at.asitplus.crypto.datatypes.pki

import at.asitplus.crypto.datatypes.asn1.*
import kotlinx.serialization.Serializable

@Serializable
data class Pkcs10CertificationRequestAttribute(
    val id: ObjectIdentifier,
    val value: List<Asn1Element>
) : Asn1Encodable<Asn1Sequence> {
    constructor(id: ObjectIdentifier, value: Asn1Element) : this(id, listOf(value))

    override fun encodeToTlv() = asn1Sequence {
        oid { id }
        set { value.forEach { append { it } } }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Pkcs10CertificationRequestAttribute

        if (id != other.id) return false
        if (value != other.value) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + value.hashCode()
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, Pkcs10CertificationRequestAttribute> {
        override fun decodeFromTlv(src: Asn1Sequence): Pkcs10CertificationRequestAttribute {
            val id = (src.children[0] as Asn1Primitive).readOid()
            val value = (src.children.last() as Asn1Set).children
            return Pkcs10CertificationRequestAttribute(id, value)
        }
    }

}