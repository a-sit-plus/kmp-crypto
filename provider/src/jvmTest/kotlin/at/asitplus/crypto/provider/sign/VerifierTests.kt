package at.asitplus.crypto.provider.sign

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.datatypes.fromJcaPublicKey
import at.asitplus.crypto.datatypes.jcaAlgorithmComponent
import at.asitplus.crypto.datatypes.jcaName
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.Security
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.random.Random

class VerifierTests: FreeSpec({
    withData(mapOf<String, (SignatureAlgorithm.ECDSA, CryptoPublicKey.EC)->Verifier.EC>(
        "BC -> PlatformVerifier" to { a,k -> PlatformECDSAVerifier(a,k) },
        "BC -> KotlinVerifier" to ::KotlinECDSAVerifier)) { factory ->
        withData(ECCurve.entries) { curve ->
            withData(nameFn = SignatureInputFormat::jcaAlgorithmComponent, listOf<Digest?>(null) + Digest.entries) { digest ->
                withData(nameFn = { (key,_,_) -> key.publicPoint.toString() }, generateSequence {
                    val keypair = KeyPairGenerator.getInstance("EC", "BC").also {
                        it.initialize(ECGenParameterSpec(curve.jcaName))
                    }.genKeyPair()
                    val publicKey = CryptoPublicKey.fromJcaPublicKey(keypair.public).getOrThrow() as CryptoPublicKey.EC
                    val data = Random.nextBytes(256)
                    val sig = Signature.getInstance("${digest.jcaAlgorithmComponent}withECDSA","BC").run {
                        initSign(keypair.private)
                        update(data)
                        sign()
                    }.let(CryptoSignature::decodeFromDer)
                    keypair.public.encoded
                    Triple(publicKey, data, sig)
                }.take(5)) { (key, data, sig) ->
                    val verifier = factory(SignatureAlgorithm.ECDSA(digest, null), key)
                    verifier.verify(byteArrayOf(), sig).isSuccess shouldBe false
                    if (digest != null) {
                        verifier.verify(data.copyOfRange(0, 128), sig).isSuccess shouldBe false
                        verifier.verify(data + Random.nextBytes(8), sig).isSuccess shouldBe false
                    }
                    verifier.verify(data, sig).isSuccess shouldBe true
                }
            }
        }
    }
}) { companion object { init { Security.addProvider(BouncyCastleProvider())}}}
