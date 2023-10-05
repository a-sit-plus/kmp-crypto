import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.JwsAlgorithm
import at.asitplus.crypto.datatypes.TbsCertificate
import at.asitplus.crypto.datatypes.X509Certificate
import at.asitplus.crypto.datatypes.asn1.JwsExtensions.ensureSize
import at.asitplus.crypto.datatypes.fromJcaKey
import at.asitplus.crypto.datatypes.jcaName
import io.kotest.core.spec.style.FreeSpec
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
import java.util.Date
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
        val cryptoPublicKey = CryptoPublicKey.Ec.fromJcaKey(ecPublicKey)
        cryptoPublicKey.shouldNotBeNull()

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
        val signatureAlgorithm = JwsAlgorithm.ES256
        val contentSigner: ContentSigner = JcaContentSignerBuilder(signatureAlgorithm.jcaName).build(keyPair.private)
        val certificateHolder = builder.build(contentSigner)

        // create certificate with our structure
        val tbsCertificate = TbsCertificate(
            version = 2,
            serialNumber = serialNumber.toLong(),
            issuerCommonName = commonName,
            validFrom = notBeforeDate.toInstant().toKotlinInstant(),
            validUntil = notAfterDate.toInstant().toKotlinInstant(),
            signatureAlgorithm = signatureAlgorithm,
            subjectCommonName = commonName,
            publicKey = cryptoPublicKey
        )
        val signed = Signature.getInstance(signatureAlgorithm.jcaName).apply {
            initSign(keyPair.private)
            update(tbsCertificate.encodeToDer())
        }.sign()
        val x509Certificate = X509Certificate(tbsCertificate, signatureAlgorithm, signed)

        val kotlinEncoded = x509Certificate.encodeToDer()
        val jvmEncoded = certificateHolder.encoded
        println("Certificates will never entirely match because of randomness in ECDSA signature")
        //kotlinEncoded shouldBe jvmEncoded
        println(kotlinEncoded.encodeToString(Base16()))
        println(jvmEncoded.encodeToString(Base16()))

        kotlinEncoded.drop(7).take(228) shouldBe jvmEncoded.drop(7).take(228)

        val parsedFromKotlinCertificate =
            CertificateFactory.getInstance("X.509").generateCertificate(kotlinEncoded.inputStream())
        parsedFromKotlinCertificate.verify(keyPair.public)
    }

    "Certificate can be parsed" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)

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
        val signatureAlgorithm = JwsAlgorithm.ES256
        val contentSigner: ContentSigner = JcaContentSignerBuilder(signatureAlgorithm.jcaName).build(keyPair.private)
        val certificateHolder = builder.build(contentSigner)

        val x509Certificate = X509Certificate.decodeFromDer(certificateHolder.encoded)
        x509Certificate.shouldNotBeNull()

        //x509Certificate.encodeToDer() shouldBe certificateHolder.encoded
        x509Certificate.signatureAlgorithm shouldBe signatureAlgorithm
        x509Certificate.tbsCertificate.version shouldBe 2
        x509Certificate.tbsCertificate.issuerCommonName shouldBe commonName
        x509Certificate.tbsCertificate.subjectCommonName shouldBe commonName
        x509Certificate.tbsCertificate.serialNumber shouldBe serialNumber.longValueExact()
        x509Certificate.tbsCertificate.signatureAlgorithm shouldBe signatureAlgorithm
        x509Certificate.tbsCertificate.validFrom shouldBe notBeforeDate.toInstant().truncatedTo(ChronoUnit.SECONDS)
            .toKotlinInstant()
        x509Certificate.tbsCertificate.validUntil shouldBe notAfterDate.toInstant().truncatedTo(ChronoUnit.SECONDS)
            .toKotlinInstant()
        val parsedPublicKey = x509Certificate.tbsCertificate.publicKey
        parsedPublicKey.shouldBeInstanceOf<CryptoPublicKey.Ec>()
        parsedPublicKey.x shouldBe keyX
        parsedPublicKey.y shouldBe keyY
    }

})
