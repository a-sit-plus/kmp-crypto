import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.asn1.Asn1Element
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.parse
import at.asitplus.crypto.datatypes.fromJcaPublicKey
import at.asitplus.crypto.datatypes.getJcaPublicKey
import at.asitplus.crypto.datatypes.io.Base64Strict
import at.asitplus.crypto.datatypes.io.BitSet
import at.asitplus.crypto.datatypes.io.toBitSet
import at.asitplus.crypto.datatypes.misc.UVarInt
import com.ionspin.kotlin.bignum.integer.toBigInteger
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldStartWith
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.Security
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class PublicKeyTest : FreeSpec({
    Security.addProvider(BouncyCastleProvider())

    "SECP256 modulus correct" {
        EcCurve.SECP_256_R_1.modulus shouldBe
                (2.toBigInteger().shl(223)
                        * (2.toBigInteger().shl(31) - 1.toBigInteger())
                        + 2.toBigInteger().shl(191)
                        + 2.toBigInteger().shl(95)
                        - 1.toBigInteger())
    }

    "SECP384 modulus correct" {
        EcCurve.SECP_384_R_1.modulus shouldBe
                (2.toBigInteger().shl(383)
                        - 2.toBigInteger().shl(127)
                        - 2.toBigInteger().shl(95)
                        + 2.toBigInteger().shl(31)
                        - 1.toBigInteger())
    }

    "SECP521 modulus correct" {
        EcCurve.SECP_521_R_1.modulus shouldBe
                (2.toBigInteger().shl(520)
                        - 1.toBigInteger())
    }

    "UVarInt test" {
        val long = 0x1290uL

        val tes = UVarInt.encode(long)
        val tes2 = UVarInt(tes.bytes)
        val res = tes.decode().also { print("${tes.bytes.size}") }
        val res2 = tes2.decode()
        res shouldBe long
        res2 shouldBe res
    }

    "EC" - {
        withData(256, 384, 521) { bits ->
            val keys = List<ECPublicKey>(25600 / bits) {
                val ecKp = KeyPairGenerator.getInstance("EC", "BC").apply {
                    initialize(bits)
                }.genKeyPair()
                ecKp.public as ECPublicKey
            }
            withData(
                nameFn = {
                    "(x: ${
                        it.w.affineX.toByteArray().encodeToString(Base64Strict)
                    } y: ${it.w.affineY.toByteArray().encodeToString(Base64Strict)})"
                },
                keys
            ) { pubKey ->

                val own = CryptoPublicKey.Ec.fromJcaPublicKey(pubKey).getOrThrow()

                withClue("Basic Conversions") {
                    println(Json.encodeToString(own))
                    println(own.iosEncoded.encodeToString(Base16()))
                    println(own.encodeToDer().encodeToString(Base16()))
                    println(own.didEncoded)
                    own.encodeToDer() shouldBe pubKey.encoded
                    CryptoPublicKey.fromDid(own.didEncoded) shouldBe own
                    own.getJcaPublicKey().getOrThrow().encoded shouldBe pubKey.encoded
                    CryptoPublicKey.decodeFromTlv(Asn1Element.parse(own.encodeToDer()) as Asn1Sequence) shouldBe own
                }
                withClue("Compressed Test") {
                    val compressedPresentation = (own as CryptoPublicKey.Ec).toAnsiX963Encoded(true)
                    val fromCompressed = CryptoPublicKey.Ec.fromAnsiX963Bytes(compressedPresentation)

                    // bouncy castle compressed representation is calculated by exposing public coordinate from key and then encode that
                    compressedPresentation shouldBe (pubKey as BCECPublicKey).q.getEncoded(true)
                    fromCompressed shouldBe own
                }
            }
        }

        "Equality tests" {
            val keyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair()
            val pubKey1 = CryptoPublicKey.decodeFromDer(keyPair.public.encoded)
            val pubKey2 = CryptoPublicKey.decodeFromDer(keyPair.public.encoded)

            pubKey1.hashCode() shouldBe pubKey2.hashCode()
            pubKey1 shouldBe pubKey2
        }

        "DID Tests" {
            val listOfDidKeys = javaClass.classLoader.getResourceAsStream("did_keys.txt")?.reader()?.readLines()
                ?: throw Exception("Test vectors missing!")
            for (key in listOfDidKeys) {
                kotlin.runCatching { CryptoPublicKey.fromDid(key) }.wrap().getOrThrow()
            }
        }
    }

    "RSA" - {
        withData(512, 1024, 2048, 3072, 4096) { bits ->
            val keys = List<RSAPublicKey>(13000 / bits) {
                val rsaKP = KeyPairGenerator.getInstance("RSA").apply {
                    initialize(bits)
                }.genKeyPair()
                rsaKP.public as RSAPublicKey
            }
            withData(
                nameFn = {
                    "(n: ${
                        it.modulus.toByteArray().encodeToString(Base64Strict)
                    } e: ${it.publicExponent.toInt()})"
                },
                keys
            ) { pubKey ->

                val own = CryptoPublicKey.Rsa(pubKey.modulus.toByteArray(), pubKey.publicExponent.toInt())
                val own1 = CryptoPublicKey.Rsa(
                    ByteArray((0..10).random()) { 0 } + pubKey.modulus.toByteArray(),
                    pubKey.publicExponent.toInt()
                )

                // Correctly drops leading zeros
                own1.n shouldBe own.n
                own1.e shouldBe own.e

                println(Json.encodeToString(own))
                println(own.pkcsEncoded.encodeToString(Base16()))
                println(own.didEncoded)
                val keyBytes = ((ASN1InputStream(pubKey.encoded).readObject()
                    .toASN1Primitive() as ASN1Sequence).elementAt(1) as DERBitString).bytes
                own.pkcsEncoded shouldBe keyBytes //PKCS#1
                own.encodeToDer() shouldBe pubKey.encoded //PKCS#8
                CryptoPublicKey.decodeFromTlv(Asn1Element.parse(own.encodeToDer()) as Asn1Sequence) shouldBe own
                own.getJcaPublicKey().getOrThrow().encoded shouldBe pubKey.encoded
            }
        }
        "Equality tests" {
            val keyPair = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048) }.genKeyPair()
            val pubKey1 = CryptoPublicKey.decodeFromDer(keyPair.public.encoded)
            val pubKey2 = CryptoPublicKey.decodeFromDer(keyPair.public.encoded)

            pubKey1.hashCode() shouldBe pubKey2.hashCode()
            pubKey1 shouldBe pubKey2
        }
    }

    "EC and RSA" - {
        withData(512, 1024, 2048, 3072, 4096) { rsaBits ->
            withData(256, 384, 521) { ecBits ->
                val keyPairEC1 = KeyPairGenerator.getInstance("EC").also { it.initialize(ecBits) }.genKeyPair()
                val keyPairEC2 = KeyPairGenerator.getInstance("EC").also { it.initialize(ecBits) }.genKeyPair()
                val keyPairRSA1 = KeyPairGenerator.getInstance("RSA").also { it.initialize(rsaBits) }.genKeyPair()
                val keyPairRSA2 = KeyPairGenerator.getInstance("RSA").also { it.initialize(rsaBits) }.genKeyPair()
                val pubKey1 = CryptoPublicKey.decodeFromDer(keyPairEC1.public.encoded)
                val pubKey2 = CryptoPublicKey.decodeFromDer(keyPairEC2.public.encoded)
                val pubKey3 = CryptoPublicKey.decodeFromDer(keyPairRSA1.public.encoded)
                val pubKey4 = CryptoPublicKey.decodeFromDer(keyPairRSA2.public.encoded)

                pubKey1.hashCode() shouldNotBe pubKey2.hashCode()
                pubKey1.hashCode() shouldNotBe pubKey3.hashCode()
                pubKey1.hashCode() shouldNotBe pubKey4.hashCode()
                pubKey3.hashCode() shouldNotBe pubKey4.hashCode()
                pubKey3.hashCode() shouldNotBe pubKey2.hashCode()
                pubKey4.hashCode() shouldNotBe pubKey2.hashCode()
                pubKey1 shouldNotBe pubKey2
                pubKey1 shouldNotBe pubKey3
                pubKey1 shouldNotBe pubKey4
                pubKey3 shouldNotBe pubKey4
                pubKey3 shouldNotBe pubKey2
                pubKey4 shouldNotBe pubKey2
            }
        }
    }
})
