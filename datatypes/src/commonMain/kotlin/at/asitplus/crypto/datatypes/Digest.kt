package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.Identifiable
import at.asitplus.crypto.datatypes.asn1.KnownOIDs
import at.asitplus.crypto.datatypes.asn1.ObjectIdentifier
import at.asitplus.crypto.datatypes.misc.BitLength

/**
 * Currently, we only support SHA-256
 */
enum class Digest(override val oid: ObjectIdentifier) : Identifiable {

    SHA1(KnownOIDs.sha1),
    SHA256(KnownOIDs.sha_256),
    SHA384(KnownOIDs.sha_384),
    SHA512(KnownOIDs.sha_512);

    val outputLength: BitLength inline get() = when(this) {
        SHA1 -> 160u
        SHA256 -> 256u
        SHA384 -> 384u
        SHA512 -> 512u
    }.let(::BitLength)
}
