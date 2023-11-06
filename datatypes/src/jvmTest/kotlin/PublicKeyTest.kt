import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.asn1.Asn1Element
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.parse
import at.asitplus.crypto.datatypes.fromJcaKey
import at.asitplus.crypto.datatypes.getPublicKey
import at.asitplus.crypto.datatypes.io.Base64Strict
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERBitString
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class PublicKeyTest : FreeSpec({
    "EC" - {
        withData(256, 384, 521) { bits ->
            val keys = List<ECPublicKey>(256000 / bits) {
                val ecKp = KeyPairGenerator.getInstance("EC").apply {
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

                val own = CryptoPublicKey.Ec.fromJcaKey(pubKey)
                own.shouldNotBeNull()
                println(Json.encodeToString(own))
                println(own.iosEncoded.encodeToString(Base16()))
                println(own.encodeToDer().encodeToString(Base16()))
                println(own.keyId)
                own.encodeToDer() shouldBe pubKey.encoded
                CryptoPublicKey.fromKeyId(own.keyId) shouldBe own
                own.getPublicKey().encoded shouldBe pubKey.encoded
                CryptoPublicKey.decodeFromTlv(Asn1Element.parse(own.encodeToDer()) as Asn1Sequence) shouldBe own
            }
        }

        "Equality tests" {
            val keyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair()
            val pubKey1 = CryptoPublicKey.derDecode(keyPair.public.encoded)
            val pubKey2 = CryptoPublicKey.derDecode(keyPair.public.encoded)

            pubKey1.hashCode() shouldBe pubKey2.hashCode()
            pubKey1 shouldBe pubKey2
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
                println(own.iosEncoded.encodeToString(Base16()))
                println(own.keyId)
                val keyBytes = ((ASN1InputStream(pubKey.encoded).readObject()
                    .toASN1Primitive() as ASN1Sequence).elementAt(1) as DERBitString).bytes
                own.iosEncoded shouldBe keyBytes //PKCS#1
                own.encodeToDer() shouldBe pubKey.encoded //PKCS#8
                CryptoPublicKey.decodeFromTlv(Asn1Element.parse(own.encodeToDer()) as Asn1Sequence) shouldBe own
                own.getPublicKey().encoded shouldBe pubKey.encoded
            }
        }
        "Equality tests" {
            val keyPair = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048) }.genKeyPair()
            val pubKey1 = CryptoPublicKey.derDecode(keyPair.public.encoded)
            val pubKey2 = CryptoPublicKey.derDecode(keyPair.public.encoded)

            pubKey1.hashCode() shouldBe pubKey2.hashCode()
            pubKey1 shouldBe pubKey2
        }
    }
})
