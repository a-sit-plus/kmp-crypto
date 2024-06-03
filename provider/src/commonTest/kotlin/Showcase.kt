import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.provider.CryptoProvider
import at.asitplus.crypto.provider.private
import io.kotest.core.spec.style.FreeSpec

class Showcase : FreeSpec({
    "DummyTest" {
        val newKey = CryptoProvider.createSigningKey(TEST_KEY_ALIAS, CryptoAlgorithm.ES256, platformCryptoOpts)

        CryptoProvider.deleteEntry(TEST_KEY_ALIAS, newKey.getOrThrow().private.platformSpecifics)
    }
})
