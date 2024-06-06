package sign

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.fromJcaPublicKey
import at.asitplus.crypto.datatypes.jcaName
import at.asitplus.crypto.provider.sign.InvalidSignature
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
    "BouncyCastle tests" - {
        withData(ECCurve.entries) { curve ->
            withData(listOf<Digest?>(null) + Digest.entries) { digest ->
                withData(nameFn = { (key, data, sig) -> key.publicPoint.toString() }, generateSequence {
                    val keypair = KeyPairGenerator.getInstance("EC", "BC").also {
                        it.initialize(ECGenParameterSpec(curve.jcaName))
                    }.genKeyPair()
                    val publicKey = CryptoPublicKey.fromJcaPublicKey(keypair.public).getOrThrow() as CryptoPublicKey.EC
                    val data = Random.nextBytes(256)
                    val sig = Signature.getInstance("${digest?.jcaName ?: "None"}withECDSA","BC").run {
                        initSign(keypair.private)
                        update(data)
                        sign()
                    }.let(CryptoSignature::decodeFromDer)
                    Triple(publicKey, data, sig)
                }.take(50)) { (key, data, sig) ->
                    val verifier = Verifier.EC(key, digest)
                    shouldThrow<InvalidSignature> { verifier.verify(byteArrayOf(), sig) }
                    shouldNotThrowAny { verifier.verify(data, sig) }
                }
            }
        }
    }
}) { companion object { init { Security.addProvider(BouncyCastleProvider())}}}
