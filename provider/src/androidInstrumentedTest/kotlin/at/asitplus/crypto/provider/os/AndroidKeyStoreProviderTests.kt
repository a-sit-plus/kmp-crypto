package at.asitplus.crypto.provider.os

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.provider.sign.Signer
import at.asitplus.crypto.provider.sign.sign
import at.asitplus.crypto.provider.sign.verifierFor
import at.asitplus.crypto.provider.sign.verify
import br.com.colman.kotest.FreeSpec
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.property.azstring
import org.junit.runner.RunWith
import kotlin.random.Random

class AndroidKeyStoreProviderTests: FreeSpec({
    "Create attested keypair" {
        val alias = Random.azstring(32)
        val attestChallenge = Random.nextBytes(32)
        val hardwareSigner = AndroidKeyStoreProvider().createSigningKey(alias) {
            tpm {
                attestation {
                    challenge = attestChallenge
                }
            }
        }.getOrThrow()
        val publicKey = hardwareSigner.publicKey
        publicKey.shouldBeInstanceOf<CryptoPublicKey.EC>()

        val plaintext = Random.nextBytes(64)
        val signature = hardwareSigner.sign(plaintext).getOrThrow()

        SignatureAlgorithm.ECDSAwithSHA256.verifierFor(publicKey).getOrThrow()
            .verify(plaintext, signature).getOrThrow()

        val certificateChain = hardwareSigner.certificateChain
        // TODO verify attestation
    }
})
