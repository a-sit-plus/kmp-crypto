import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.cose.CoseAlgorithm
import at.asitplus.crypto.datatypes.cose.CoseKey
import at.asitplus.crypto.datatypes.cose.io.cborSerializer
import at.asitplus.crypto.datatypes.cose.toCoseKey
import at.asitplus.crypto.datatypes.fromJcaKey
import at.asitplus.crypto.datatypes.io.Base64Strict
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class CoseKeySerializationTest : FreeSpec({

    "Serializing" - {
        "Manual" {
            val cose =
                cborSerializer.encodeToByteArray(
                    arrayOf(
                        CryptoPublicKey.fromJcaKey(
                            KeyPairGenerator.getInstance("EC").apply {
                                initialize(256)
                            }.genKeyPair().public
                        )!!.toCoseKey().getOrThrow(), CryptoPublicKey.fromJcaKey(KeyPairGenerator.getInstance("EC").apply {
                            initialize(256)
                        }.genKeyPair().public)!!.toCoseKey().getOrThrow()
                    )
                )
            println(cose.encodeToString(Base16))
            val decoded = cborSerializer.decodeFromByteArray<Array<CoseKey>>(cose)
            println(decoded)
        }


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

                    val coseKey = CryptoPublicKey.fromJcaKey(pubKey)!!.toCoseKey().getOrThrow()
                    val cose =
                        cborSerializer.encodeToByteArray(coseKey)
                    println(cose.encodeToString(Base16))
                    val decoded = cborSerializer.decodeFromByteArray<CoseKey>(cose)
                    decoded shouldBe coseKey
                    println(decoded)
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

                    val coseKey = CryptoPublicKey.fromJcaKey(pubKey)!!.toCoseKey(CoseAlgorithm.RS256).getOrThrow()
                    val cose =
                        cborSerializer.encodeToByteArray(coseKey)
                    println(cose.encodeToString(Base16))
                    val decoded = cborSerializer.decodeFromByteArray<CoseKey>(cose)
                    decoded shouldBe coseKey
                    println(decoded)
                }
            }
        }
    }
})