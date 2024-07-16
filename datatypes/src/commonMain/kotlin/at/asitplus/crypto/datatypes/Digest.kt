package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.Identifiable
import at.asitplus.crypto.datatypes.asn1.KnownOIDs
import at.asitplus.crypto.datatypes.asn1.ObjectIdentifier
import at.asitplus.crypto.datatypes.misc.BitLength
import at.asitplus.crypto.datatypes.misc.bit

enum class Digest(val outputLength: BitLength, override val oid: ObjectIdentifier) : Identifiable {
    SHA1(160.bit, KnownOIDs.sha1),
    SHA256(256.bit, KnownOIDs.sha_256),
    SHA384(384.bit, KnownOIDs.sha_384),
    SHA512(512.bit, KnownOIDs.sha_512);
}

val ECCurve.nativeDigest get() = when (this) {
    ECCurve.SECP_256_R_1 -> Digest.SHA256
    ECCurve.SECP_384_R_1 -> Digest.SHA384
    ECCurve.SECP_521_R_1 -> Digest.SHA512
}
