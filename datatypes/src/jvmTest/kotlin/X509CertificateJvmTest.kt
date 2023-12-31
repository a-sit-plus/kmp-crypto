import at.asitplus.crypto.datatypes.*
import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.pki.DistinguishedName
import at.asitplus.crypto.datatypes.pki.TbsCertificate
import at.asitplus.crypto.datatypes.pki.X509Certificate
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.toKotlinInstant
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import kotlin.math.absoluteValue
import kotlin.random.Random
import kotlin.time.Duration.Companion.days

class X509CertificateJvmTest : FreeSpec({

    lateinit var ecCurve: EcCurve
    lateinit var keyPair: KeyPair

    beforeTest {
        ecCurve = EcCurve.SECP_256_R_1
        keyPair = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
    }

    "Certificates match" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val cryptoPublicKey = CryptoPublicKey.Ec.fromJcaPublicKey(ecPublicKey).getOrThrow()

        // create certificate with bouncycastle
        val notBeforeDate = Date.from(Instant.now())
        val notAfterDate = Date.from(Instant.now().plusSeconds(30.days.inWholeSeconds))
        val serialNumber: BigInteger = BigInteger.valueOf(Random.nextLong().absoluteValue)
        val commonName = "DefaultCryptoService"
        val issuer = X500Name("CN=$commonName")
        val builder = X509v3CertificateBuilder(
            /* issuer = */ issuer,
            /* serial = */ serialNumber,
            /* notBefore = */ notBeforeDate,
            /* notAfter = */ notAfterDate,
            /* subject = */ issuer,
            /* publicKeyInfo = */ SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        )
        val signatureAlgorithm = CryptoAlgorithm.ES256
        val contentSigner: ContentSigner = JcaContentSignerBuilder(signatureAlgorithm.jcaName).build(keyPair.private)
        val certificateHolder = builder.build(contentSigner)

        // create certificate with our structure
        val tbsCertificate = TbsCertificate(
            version = 2,
            serialNumber = serialNumber.toByteArray(),
            issuerName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
            validFrom = Asn1Time(notBeforeDate.toInstant().toKotlinInstant()),
            validUntil = Asn1Time(notAfterDate.toInstant().toKotlinInstant()),
            signatureAlgorithm = signatureAlgorithm,
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
            publicKey = cryptoPublicKey
        )
        val signed = Signature.getInstance(signatureAlgorithm.jcaName).apply {
            initSign(keyPair.private)
            update(tbsCertificate.encodeToTlv().derEncoded)
        }.sign()
        val test = CryptoSignature.decodeFromDer(signed)
        val x509Certificate = X509Certificate(tbsCertificate, signatureAlgorithm, test)

        val kotlinEncoded = x509Certificate.encodeToDer()
        val jvmEncoded = certificateHolder.encoded
        println(
            "Certificates will never entirely match because of randomness in ECDSA signature" +
                    "\nKotlinEncoded\n" +
                    kotlinEncoded.encodeToString(Base16()) +
                    "\nJvmEncoded\n" +
                    jvmEncoded.encodeToString(Base16())
        )
        kotlinEncoded.drop(7).take(228) shouldBe jvmEncoded.drop(7).take(228)

        val parsedFromKotlinCertificate =
            CertificateFactory.getInstance("X.509").generateCertificate(kotlinEncoded.inputStream())
        parsedFromKotlinCertificate.verify(keyPair.public)
    }

    "Certificate can be parsed" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val cryptoPublicKey = CryptoPublicKey.Ec(curve = ecCurve, x = keyX, y = keyY)

        // create certificate with bouncycastle
        val notBeforeDate = Date.from(Instant.now())
        val notAfterDate = Date.from(Instant.now().plusSeconds(30.days.inWholeSeconds))
        val serialNumber: BigInteger = BigInteger.valueOf(Random.nextLong().absoluteValue)
        val commonName = "DefaultCryptoService"
        val issuer = X500Name("CN=$commonName")
        val builder = X509v3CertificateBuilder(
            /* issuer = */ issuer,
            /* serial = */ serialNumber,
            /* notBefore = */ notBeforeDate,
            /* notAfter = */ notAfterDate,
            /* subject = */ issuer,
            /* publicKeyInfo = */ SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        )
        val signatureAlgorithm = CryptoAlgorithm.ES256
        val contentSigner: ContentSigner = JcaContentSignerBuilder(signatureAlgorithm.jcaName).build(keyPair.private)
        val certificateHolder = builder.build(contentSigner)

        val x509Certificate =
            X509Certificate.decodeFromTlv(Asn1Element.parse(certificateHolder.encoded) as Asn1Sequence)
        x509Certificate.shouldNotBeNull()

        //x509Certificate.encodeToDer() shouldBe certificateHolder.encoded
        x509Certificate.signatureAlgorithm shouldBe signatureAlgorithm
        x509Certificate.tbsCertificate.version shouldBe 2
        (x509Certificate.tbsCertificate.issuerName.first().value as Asn1Primitive).content shouldBe commonName.encodeToByteArray()
        (x509Certificate.tbsCertificate.subjectName.first().value as Asn1Primitive).content shouldBe commonName.encodeToByteArray()
        x509Certificate.tbsCertificate.serialNumber shouldBe serialNumber.toByteArray()
        x509Certificate.tbsCertificate.signatureAlgorithm shouldBe signatureAlgorithm
        x509Certificate.tbsCertificate.validFrom.instant shouldBe notBeforeDate.toInstant()
            .truncatedTo(ChronoUnit.SECONDS)
            .toKotlinInstant()
        x509Certificate.tbsCertificate.validUntil.instant shouldBe notAfterDate.toInstant()
            .truncatedTo(ChronoUnit.SECONDS)
            .toKotlinInstant()
        val parsedPublicKey = x509Certificate.tbsCertificate.publicKey
        parsedPublicKey.shouldBeInstanceOf<CryptoPublicKey.Ec>()
        parsedPublicKey.x shouldBe keyX
        parsedPublicKey.y shouldBe keyY
    }

    "Certificate can be parsed to tree" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val cryptoPublicKey = CryptoPublicKey.Ec(curve = ecCurve, x = keyX, y = keyY)

        // create certificate with bouncycastle
        val notBeforeDate = Date.from(Instant.now())
        val notAfterDate = Date.from(Instant.now().plusSeconds(30.days.inWholeSeconds))
        val serialNumber: BigInteger = BigInteger.valueOf(Random.nextLong().absoluteValue)
        val commonName = "DefaultCryptoService"
        val issuer = X500Name("CN=$commonName")
        val builder = X509v3CertificateBuilder(
            /* issuer = */ issuer,
            /* serial = */ serialNumber,
            /* notBefore = */ notBeforeDate,
            /* notAfter = */ notAfterDate,
            /* subject = */ issuer,
            /* publicKeyInfo = */ SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        )
        val signatureAlgorithm = CryptoAlgorithm.ES256
        val contentSigner: ContentSigner = JcaContentSignerBuilder(signatureAlgorithm.jcaName).build(keyPair.private)
        val certificateHolder = builder.build(contentSigner)

        println(certificateHolder.encoded.encodeToString(Base16))
        val parsed = Asn1Element.parse(certificateHolder.encoded)

        println(parsed)
        val matches = listOf(parsed).expect {
            sequence {
                sequence {
                    tag(0xA0u)
                    long()
                    sequence {
                        oid()
                    }
                    sequence {
                        set {
                            sequence {
                                oid()
                                utf8String()
                            }
                        }
                    }
                    sequence {
                        utcTime()
                        utcTime()
                    }
                    sequence {
                        set {
                            sequence {
                                oid()
                                utf8String()
                            }
                        }
                    }
                    sequence {
                        // SPKI!
                    }
                }
                sequence {
                    oid()
                }
                bitString()
            }
        }
        matches.shouldBeTrue()
    }


})


fun List<Asn1Element>.expect(init: SequenceReader.() -> Unit): Boolean {
    val seq = SequenceReader(this)
    seq.init()
    return seq.matches
}


class SequenceReader(var asn1Elements: List<Asn1Element>) {
    var matches: Boolean = true

    fun sequence(function: SequenceReader.() -> Unit) = container(0x30u, function)
    fun set(function: SequenceReader.() -> Unit) = container(0x31u, function)

    fun integer() = tag(0x02u)
    fun long() = tag(0x02u)
    fun bitString() = tag(0x03u)
    fun oid() = tag(0x06u)
    fun utf8String() = tag(0x0cu)
    fun utcTime() = tag(0x17u)

    fun container(tag: UByte, function: SequenceReader.() -> Unit) {
        val first = takeAndDrop()
        if (first.tag != tag)
            matches = false
        matches = matches and (first as Asn1Structure).children.expect(function)
    }

    fun tag(tag: UByte) {
        if (takeAndDrop().tag != tag)
            matches = false
    }

    private fun takeAndDrop() = asn1Elements.first()
        .also { asn1Elements = asn1Elements.drop(1) }

}