package sign

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.getJcaPublicKey
import at.asitplus.crypto.datatypes.jcaAlgorithmComponent
import at.asitplus.crypto.datatypes.jcaName
import at.asitplus.crypto.datatypes.jcaSignatureBytes
import at.asitplus.crypto.datatypes.pki.leaf
import at.asitplus.crypto.datatypes.toJcaCertificate
import at.asitplus.crypto.provider.sign.JavaKeyStoreProvider
import at.asitplus.crypto.provider.sign.JavaSigningKeyConfiguration
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeTypeOf
import java.security.Signature
import kotlin.random.Random
import kotlin.random.nextInt

class SignerTests : FreeSpec({
    "Key lifecycle" {
        val provider = JavaKeyStoreProvider()
        val name = "Steve"
        provider.hasSigningKey(name) shouldBe false
        provider.createSigningKey(name)
        provider.hasSigningKey(name) shouldBe true
        shouldThrowAny { provider.createSigningKey(name) }
        provider.deleteSigningKey(name)
        provider.hasSigningKey(name) shouldBe false
    }
    "Key Passwords" {
        val provider = JavaKeyStoreProvider()
        val password = "shark".toCharArray()
        val wrongPassword = "dolphin".toCharArray()
        val name = "John"
        provider.createSigningKey(name) { privateKeyPassword = password }
        shouldThrowAny { provider.getSignerForKey(name).sign(byteArrayOf()) }
        shouldThrowAny { provider.getSignerForKey(name) { privateKeyPassword = wrongPassword}.sign(byteArrayOf()) }
        shouldNotThrowAny { provider.getSignerForKey(name) { privateKeyPassword = password }.sign(byteArrayOf()) }
    }
    "Signature validation" - {
        withData(nameFn={(o,_,_)->o},sequence<Triple<String, Boolean, (JavaSigningKeyConfiguration.()->Unit)>> {
            for (i in 1..50) yield(Triple("EC #$i", true) { ec { curve = ECCurve.entries.random() }})
            for (i in 1..20) yield(Triple("RSA #$i", false) { rsa { bits = arrayOf(1024, 2048, 4096).random() }})
        }) { (_,isEC,config) ->
            val provider = JavaKeyStoreProvider()
            val name = "Martha"
            val publicKey = provider.createSigningKey(name, config)
            if (isEC)
                publicKey.shouldBeTypeOf<CryptoPublicKey.EC>()
            else
                publicKey.shouldBeTypeOf<CryptoPublicKey.Rsa>()

            val signer = provider.getSignerForKey(name)
            signer.publicKey shouldBe publicKey
            /* valid self signature on chain */
            signer.certificateChain.leaf.toJcaCertificate().getOrThrow()
                .verify(publicKey.getJcaPublicKey().getOrThrow(), "BC")
            /* correctly signs data */
            val data = Random.nextBytes(42)
            val signature = signer.sign(data)
            val algName = "${signer.nativeSignatureFormat.jcaAlgorithmComponent}with${if (isEC) "ECDSA" else "RSA"}"
            Signature.getInstance(algName, "BC").run {
                initVerify(publicKey.getJcaPublicKey().getOrThrow())
                update(data)
                verify(signature.jcaSignatureBytes) shouldBe true
            }
        }
    }
})