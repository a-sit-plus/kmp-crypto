package sign

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.fromJcaPublicKey
import at.asitplus.crypto.datatypes.jcaAlgorithmComponent
import at.asitplus.crypto.datatypes.jcaName
import at.asitplus.crypto.provider.sign.InvalidSignature
import at.asitplus.crypto.provider.sign.KotlinECVerifier
import at.asitplus.crypto.provider.sign.PlatformECVerifier
import at.asitplus.crypto.provider.sign.SignatureInputFormat
import at.asitplus.crypto.provider.sign.Verifier
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.Security
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.random.Random

class VerifierTests: FreeSpec({
    withData(mapOf("BC -> PlatformVerifier" to ::PlatformECVerifier, "BC -> KotlinVerifier" to ::KotlinECVerifier)) { factory ->
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
                    val verifier = factory(key, digest)
                    shouldThrow<InvalidSignature> { verifier.verify(byteArrayOf(), sig) }
                    if (digest != null) {
                        shouldThrow<InvalidSignature> { verifier.verify(data.copyOfRange(0, 128), sig) }
                        shouldThrow<InvalidSignature> { verifier.verify(data + Random.nextBytes(8), sig) }
                    }
                    shouldNotThrowAny { verifier.verify(data, sig) }
                }
            }
        }
    }
}) { companion object { init { Security.addProvider(BouncyCastleProvider())}}}
