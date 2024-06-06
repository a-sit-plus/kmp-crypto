package at.asitplus.crypto.provider.sign

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.ecmath.plus
import at.asitplus.crypto.ecmath.times

class InvalidSignature(message: String): Throwable(message)

sealed class Verifier(val signatureFormat: SignatureInputFormat) {
    abstract val publicKey: CryptoPublicKey

    @Throws(InvalidSignature::class)
    abstract fun verify(data: SignatureInput, sig: CryptoSignature): Unit
    inline fun verify(data: ByteArray, sig: CryptoSignature) =
        verify(SignatureInput(data), sig)

    protected inline fun test(v: Boolean, error: ()->String) {
        if (!v) throw InvalidSignature(error())
    }

    class EC(override val publicKey: CryptoPublicKey.EC,
             signatureFormat: SignatureInputFormat) : Verifier(signatureFormat) {

        private val curve inline get() = publicKey.curve
        override fun verify(data: SignatureInput, sig: CryptoSignature) {
            require (sig is CryptoSignature.EC) {
                "Attempted to validate non-EC signature using EC public key" }

            when (sig) {
                is CryptoSignature.EC.DefiniteLength -> require(sig.scalarByteLength == curve.scalarLength.bytes)
                is CryptoSignature.EC.IndefiniteLength -> sig.withCurve(curve)
            }
            test((sig.r > 0) && (sig.r < curve.order)) { "r is not in [1,n-1] (r=${sig.r}, n=${curve.order})" }
            test((sig.s > 0) && (sig.s < curve.order)) { "s is not in [1,n-1] (s=${sig.s}, n=${curve.order})" }

            val z = data.convertTo(signatureFormat).asBigInteger(curve.scalarLength)
            val sInv = sig.s.modInverse(curve.order)
            val u1 = z * sInv
            val u2 = sig.r * sInv
            val point = ((u1 * curve.generator) + (u2 * publicKey.publicPoint)).run {
                    tryNormalize() ?: throw InvalidSignature("(x1,y1) = additive zero") }
            test(point.x.residue.mod(curve.order) == sig.r.mod(curve.order)) { "r != x1" }
        }
    }
}