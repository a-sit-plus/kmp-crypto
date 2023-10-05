package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.decodeFromDer
import at.asitplus.crypto.datatypes.asn1.sequence
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed
 */
@Serializable
data class TbsCertificate(
    val version: Int = 2,
    val serialNumber: Long,
    val signatureAlgorithm: JwsAlgorithm,
    val issuerCommonName: String,
    val validFrom: Instant,
    val validUntil: Instant,
    val subjectCommonName: String,
    val publicKey: CryptoPublicKey
) {
    fun encodeToDer() = sequence {
        version { version }
        long { serialNumber }
        sequence {
            sigAlg { signatureAlgorithm }
        }
        sequence {
            set {
                sequence {
                    commonName { issuerCommonName }
                }
            }
        }
        sequence {
            utcTime { validFrom }
            utcTime { validUntil }
        }
        sequence {
            set {
                sequence {
                    commonName { subjectCommonName }
                }
            }
        }
        subjectPublicKey { publicKey }
    }

    companion object {
        fun decodeFromDer(input: ByteArray): TbsCertificate? {
            return runCatching {
                val reader = Asn1Reader(input)
                val version = reader.read(0xA0) {
                    runCatching { Asn1Reader(it).readInt() }.getOrNull()
                }
                val serialNumber = reader.readLong()
                val sigAlg = reader.readSequence(JwsAlgorithm.Companion::decodeFromDer)
                val issuerCommonName = reader.readSequence(::decodeIssuerName)
                val timestamps = reader.readSequence(::decodeTimestamps)
                val subjectCommonName = reader.readSequence(::decodeIssuerName)
                val cryptoPublicKey = reader.readSequence(CryptoPublicKey.Companion::decodeFromDer)

                return TbsCertificate(
                    version = version,
                    serialNumber = serialNumber,
                    signatureAlgorithm = sigAlg,
                    issuerCommonName = issuerCommonName,
                    validFrom = timestamps.first,
                    validUntil = timestamps.second,
                    subjectCommonName = subjectCommonName,
                    publicKey = cryptoPublicKey,
                )
            }.getOrNull()
        }

        private fun decodeTimestamps(input: ByteArray): Pair<Instant, Instant>? = runCatching {
            val reader = Asn1Reader(input)
            val firstInstant = reader.readInstant()
            val secondInstant = reader.readInstant()
            return Pair(firstInstant, secondInstant)
        }.getOrNull()

        private fun decodeIssuerName(input: ByteArray) =
            runCatching { Asn1Reader(input).readSet(::decodeX500Name) }.getOrNull()

        private fun decodeX500Name(input: ByteArray) =
            runCatching { Asn1Reader(input).readSequence(::decodeRdn) }.getOrNull()

        private fun decodeRdn(input: ByteArray): String? = runCatching {
            val reader = Asn1Reader(input)
            val oid = reader.readOid()
            if (oid == "550403") {
                return reader.readUtf8String()
            }
            return null
        }.getOrNull()

    }
}

/**
 * Very simple implementation of an X.509 Certificate
 */
@Serializable
data class X509Certificate(
    val tbsCertificate: TbsCertificate,
    val signatureAlgorithm: JwsAlgorithm,
    @Serializable(with = ByteArrayBase64Serializer::class)
    val signature: ByteArray
) {
    fun encodeToDer() = sequence {
        tbsCertificate { tbsCertificate }
        sequence {
            sigAlg { signatureAlgorithm }
        }
        bitString { signature }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X509Certificate

        if (tbsCertificate != other.tbsCertificate) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCertificate.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

    companion object {
        fun decodeFromDer(input: ByteArray): X509Certificate? {
            return runCatching {
                Asn1Reader(input).readSequence(::decodeFromDerInner)
            }.getOrNull()
        }

        private fun decodeFromDerInner(input: ByteArray): X509Certificate {
            val reader = Asn1Reader(input)
            val tbs = reader.readSequence(TbsCertificate.Companion::decodeFromDer)
            val sigAlg = reader.readSequence(JwsAlgorithm.Companion::decodeFromDer)
            val signature = reader.readBitstring()
            return X509Certificate(
                tbsCertificate = tbs,
                signatureAlgorithm = sigAlg,
                signature = signature
            )
        }

    }
}
