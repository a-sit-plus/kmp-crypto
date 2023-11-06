import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.asn1.Asn1Element
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.parse
import at.asitplus.crypto.datatypes.pki.X509Certificate
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileReader
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.util.*
import java.security.cert.X509Certificate as JcaCertificate


private val json = Json { prettyPrint = true }

class X509CertParserTest : FreeSpec({

    "Manual" {
        //ok-uniqueid-incomplete-byte.der
        val derBytes =
            javaClass.classLoader.getResourceAsStream("certs/ok-uniqueid-incomplete-byte.der").readBytes()
        X509Certificate.derDecode(derBytes)
    }


    "Real Certificates" - {
        withData("digicert-root.pem", "github-com.pem", "cert-times.pem") { crt ->
            val certBytes = java.util.Base64.getMimeDecoder()
                .decode(javaClass.classLoader.getResourceAsStream(crt).reader().readText())
            val jcaCert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(certBytes)) as JcaCertificate

            println(jcaCert.encoded.encodeToString(Base16))
            val elem = Asn1Element.parse(certBytes)
        Json{prettyPrint=true}.encodeToString(elem)
            val cert = X509Certificate.derDecode(certBytes)

            when (val pk = cert.publicKey) {
                is CryptoPublicKey.Ec -> println(
                    "Certificate with serial no. ${
                        cert.tbsCertificate.serialNumber.encodeToString(Base16)
                    } contains an EC public key using curve ${pk.curve}"
                )

                is CryptoPublicKey.Rsa -> println(
                    "Certificate with serial no. ${
                        cert.tbsCertificate.serialNumber.encodeToString(Base16)
                    } contains a ${pk.bits.number} bit RSA public key"
                )
            }

            println("The full certificate is:\n${Json { prettyPrint = true }.encodeToString(cert)}")

            println("Re-encoding it produces the same bytes? ${cert.encodeToDer() contentEquals certBytes}")


            println(cert.encodeToTlv())
            println(cert.encodeToTlv().toDerHexString())

            withClue(
                "Expect: ${jcaCert.encoded.encodeToString(Base16)}\n" +
                        "Actual: ${cert.encodeToTlv().derEncoded.encodeToString(Base16)}"
            ) {
                cert.encodeToTlv().derEncoded shouldBe jcaCert.encoded
            }
        }
    }

    "system trust store" - {
        val certs = File("/etc/ssl/certs").listFiles { f: File -> f.name.endsWith(".pem") }.mapNotNull {
            runCatching { convertStringToX509Cert(FileReader(it).readText()) }.getOrNull()
        }
        val pemEncodeCerts = runCatching {
            File("/etc/ssl/certs/ca-certificates.crt").readText().split(Regex.fromLiteral("-\n-"))
                .mapNotNull {
                    var pem = if (it.startsWith("-----")) it else "-$it"
                    pem = if (!pem.endsWith("-----")) "$pem-" else pem

                    runCatching { convertStringToX509Cert(pem) }.getOrNull()
                }
        }.getOrElse {
            println("W: could not load /etc/ssl/certs/ca-certificates.crt")
            emptyList()
        }
        val uniqueCerts = (certs + pemEncodeCerts).distinctBy {
            it.encoded.encodeToString(Base64 {})
        }

        println("Got ${certs.size} discrete certs and ${pemEncodeCerts.size} from trust store (${uniqueCerts.size} unique ones)")


        withData(nameFn = { it.subjectDN.name }, uniqueCerts.sortedBy { it.subjectDN.name }) { crt ->
            val own = X509Certificate.decodeFromTlv(Asn1Element.parse(crt.encoded) as Asn1Sequence)
                .encodeToTlv().derEncoded
            withClue(
                "Expect: ${crt.encoded.encodeToString(Base16)}\n" +
                        "Actual: ${own.encodeToString(Base16)}"
            ) {
                own shouldBe crt.encoded
            }
        }
    }

    "From Google's X509 Cert Test Suite" - {

        val (ok, faulty) = readGoogleCerts()

        "OK certs should parse" - {
            val good =
                ok.filterNot { it.first == "ok-inherited-keyparams.ca.der" || it.first == "ok-inherited-keyparams.leaf.der" } //filter out certs with DSA pubKeys

            withData(nameFn = { it.first }, good) {
                val src = Asn1Element.parse(it.second) as Asn1Sequence
                println(src.prettyPrint())
                X509Certificate.decodeFromTlv(src)
            }
        }
        "Faulty certs should glitch out" - {
            withData(nameFn = { it.first }, faulty) { crt ->
                runCatching {
                    shouldThrow<Throwable> {
                        X509Certificate.decodeFromTlv(Asn1Element.parse(crt.second) as Asn1Sequence)
                    }
                }.getOrElse { println("W: ${crt.first} parsed too leniently") }
            }
        }
    }



    "From attestation collector" - {
        val json = File("./src/jvmTest/resources/results").listFiles()
            .map { Json.parseToJsonElement(it.readText()).jsonObject }
        val certs = json.mapIndexed { i, collected ->
            (collected["device"]!!.jsonPrimitive.toString() + " ($i)") to collected.get("attestationProof")!!.jsonArray.map {
                it.jsonPrimitive.toString().replace("\\n", "").replace("\\r", "").replace("\"", "")
            }
        }.toMap()

        withData(certs) {
            withData(it) {
                val encodedSrc = it.decodeToByteArray(Base64 {})

                val jcaCert = CertificateFactory
                    .getInstance("X509")
                    .generateCertificate(ByteArrayInputStream(encodedSrc)) as java.security.cert.X509Certificate

                val cert = X509Certificate.derDecode(encodedSrc)

                jcaCert.encoded shouldBe encodedSrc
                cert.encodeToTlv().derEncoded shouldBe encodedSrc
            }
        }

    }

})


private fun readGoogleCerts(): Pair<List<Pair<String, ByteArray>>, List<Pair<String, ByteArray>>> {
    val cert1 = File("./src/jvmTest/resources/certs").listFiles()
        .filter { it.extension == "der" && !it.name.contains(".chain.") }
    val certs2 =
        File("./src/jvmTest/resources/certs2").listFiles()
            .filter { it.extension == "der" && !it.name.contains(".chain.") }
    val all = cert1 + certs2

    val ok = all.filter { it.name.startsWith("ok-") }
    val faulty = all.filter { !it.name.startsWith("ok-") }
    return ok.map { it.name to it.readBytes() } to faulty.map { it.name to it.readBytes() }
}

@Throws(Exception::class)
private fun convertStringToX509Cert(certificate: String): java.security.cert.X509Certificate {
    val targetStream: InputStream = ByteArrayInputStream(certificate.toByteArray())
    return CertificateFactory
        .getInstance("X509")
        .generateCertificate(targetStream) as java.security.cert.X509Certificate
}