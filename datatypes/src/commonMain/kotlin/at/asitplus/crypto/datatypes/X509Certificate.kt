package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.decodeFromDer
import at.asitplus.crypto.datatypes.asn1.sequence
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
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
                val version = reader.read(0xA0, ::readInt)
                val serialNumber = reader.read(0x02, Long.Companion::decodeFromDer)
                val sigAlg = reader.read(0x30, JwsAlgorithm.Companion::decodeFromDer)
                val issuerCommonName = reader.read(0x30, ::decodeIssuerName)
                val timestamps = reader.read(0x30, ::decodeTimestamps)
                val subjectCommonName = reader.read(0x30, ::decodeIssuerName)
                val cryptoPublicKey = reader.read(0x30, CryptoPublicKey.Ec.Companion::decodeFromDer)

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
            val firstInstant = reader.read(0x17, Instant.Companion::decodeFromDer)
            val secondInstant = reader.read(0x17, Instant.Companion::decodeFromDer)
            return Pair(firstInstant, secondInstant)
        }.getOrNull()

        private fun decodeIssuerName(input: ByteArray) =
            runCatching { Asn1Reader(input).read(0x31, ::decodeX500Name) }.getOrNull()

        private fun decodeX500Name(input: ByteArray) =
            runCatching { Asn1Reader(input).read(0x30, ::decodeRdn) }.getOrNull()

        private fun decodeRdn(input: ByteArray): String? = runCatching {
            val reader = Asn1Reader(input)
            val oid = reader.read(0x06) { bytes -> bytes.encodeToString(Base16) }
            if (oid == "550403") {
                return reader.read(0x0c) { bytes -> String(bytes) }
            }
            return null
        }.getOrNull()

        private fun readInt(input: ByteArray) =
            runCatching { Asn1Reader(input).read(0x02, Int.Companion::decodeFromDer) }.getOrNull()

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
                Asn1Reader(input).read(0x30, ::decodeFromDerInner)
            }.getOrNull()
        }

        private fun decodeFromDerInner(input: ByteArray): X509Certificate {
            val reader = Asn1Reader(input)
            val tbs = reader.read(0x30, TbsCertificate.Companion::decodeFromDer)
            val sigAlg = reader.read(0x30, JwsAlgorithm.Companion::decodeFromDer)
            val signature = reader.read(0x03, ::decodeBitstring)
            return X509Certificate(
                tbsCertificate = tbs,
                signatureAlgorithm = sigAlg,
                signature = signature
            )
        }

    }
}
