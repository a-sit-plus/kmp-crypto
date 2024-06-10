package at.asitplus.crypto.provider.sign

import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.getJcaPublicKey
import at.asitplus.crypto.datatypes.jcaSignatureBytes
import java.security.Signature

internal actual fun verifySignaturePlatformImpl(info: Verifier.EC, data: SignatureInput, sig: CryptoSignature) {
    Signature.getInstance("NonewithECDSA","BC").run {
        initVerify(info.publicKey.getJcaPublicKey().getOrThrow())
        data.convertTo(info.signatureFormat).data.forEach(this::update)
        val result = verify(sig.jcaSignatureBytes)
        if (!result) throw InvalidSignature("Signature is invalid")
    }
}