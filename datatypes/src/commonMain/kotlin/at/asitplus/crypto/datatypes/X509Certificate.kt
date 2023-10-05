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
        fun decodeFromDer(encoded: ByteArray): TbsCertificate? {
            return runCatching {
                var rest = encoded
                val version = read(rest, 0xA0, ::readInt).also { rest = it.second }
                val serialNumber = read(rest, 0x02, Long.Companion::decodeFromDer).also { rest = it.second }
                val sigAlg = read(rest, 0x30, JwsAlgorithm.Companion::decodeFromDer).also { rest = it.second }
                val issuerCommonName = read(rest, 0x30, ::decodeIssuerName).also { rest = it.second }
                val timestamps = read(rest, 0x30, ::decodeTimestamps).also { rest = it.second }
                val subjectCommonName = read(rest, 0x30, ::decodeIssuerName).also { rest = it.second }
                val cryptoPublicKey =
                    read(rest, 0x30, CryptoPublicKey.Ec.Companion::decodeFromDer).also { rest = it.second }

                return TbsCertificate(
                    version = version.first,
                    serialNumber = serialNumber.first,
                    signatureAlgorithm = sigAlg.first,
                    issuerCommonName = issuerCommonName.first,
                    validFrom = timestamps.first.first,
                    validUntil = timestamps.first.second,
                    subjectCommonName = subjectCommonName.first,
                    publicKey = cryptoPublicKey.first,
                )
            }.getOrNull()
        }

        private fun decodeTimestamps(bytes: ByteArray): Pair<Instant, Instant>? = runCatching {
            var rest = bytes
            val firstInstant = read(rest, 0x17, Instant.Companion::decodeFromDer).also { rest = it.second }
            val secondInstant = read(rest, 0x17, Instant.Companion::decodeFromDer).also { rest = it.second }
            return Pair(firstInstant.first, secondInstant.first)
        }.getOrNull()

        private fun decodeIssuerName(bytes: ByteArray) =
            runCatching { read(bytes, 0x31, ::decodeX500Name).first }.getOrNull()

        private fun decodeX500Name(bytes: ByteArray) =
            runCatching { read(bytes, 0x30, ::decodeRdn).first }.getOrNull()

        private fun decodeRdn(bytes: ByteArray): String? = runCatching {
            var rest = bytes
            val oid = read(rest, 0x06) { bytes -> bytes.encodeToString(Base16) }
                .also { rest = it.second }
            if (oid.first == "550403") {
                return read(rest, 0x0c) { bytes -> String(bytes) }.first
            }
            return null
        }.getOrNull()

        private fun readInt(input: ByteArray) =
            runCatching { read(input, 0x02, Int.Companion::decodeFromDer).first }.getOrNull()

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
        fun decodeFromDer(encoded: ByteArray): X509Certificate? {
            return runCatching {
                read(encoded, 0x30, ::decodeFromDerInner).first
            }.getOrNull()
        }

        private fun decodeFromDerInner(input: ByteArray): X509Certificate {
            var rest = input
            val tbs = read(rest, 0x30, TbsCertificate.Companion::decodeFromDer).also { rest = it.second }
            val sigAlg = read(rest, 0x30, JwsAlgorithm.Companion::decodeFromDer).also { rest = it.second }
            val signature = read(rest, 0x03, ::decodeBitstring).also { rest = it.second }
            return X509Certificate(
                tbsCertificate = tbs.first,
                signatureAlgorithm = sigAlg.first,
                signature = signature.first
            )
        }

    }
}
