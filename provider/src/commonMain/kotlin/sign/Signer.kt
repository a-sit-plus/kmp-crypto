package at.asitplus.crypto.provider.sign

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.pki.CertificateChain
import at.asitplus.crypto.provider.UnlockFailed
import at.asitplus.crypto.provider.UnlockRequired
import kotlin.coroutines.cancellation.CancellationException

interface Signer {
    val publicKey: CryptoPublicKey
    val certificateChain: CertificateChain

    /**
     * Whether this signer can perform signatures over pre-hashed data (`true`)
     * or requires a raw message (`false`), calculating the message digest internally.
     */
    val flexibleInput: Boolean

    /**
     * The format over which the signer naturally produces signatures.
     *
     * If `requiresRawInput` is `false`, other formats can be passed, and will be signed.
     */
    val nativeSignatureFormat: SignatureInputFormat

    /**
     * Attempts to unlock this signer ahead of time.
     * This is not possible for all signers, and may fail.
     */
    @Throws(UnlockFailed::class, CancellationException::class)
    suspend fun unlock()

    /**
     * Unlocks this signer if necessary, and signs the message once unlocked.
     * If the signer is locked, this operation might suspend and request unlock from the user.
     */
    @Throws(UnlockFailed::class, CancellationException::class)
    suspend fun unlockAndSign(data: SignatureInput): CryptoSignature
    suspend fun unlockAndSign(data: ByteArray) = unlockAndSign(SignatureInput(data))

    /**
     * Signs the input with this signer.
     * This operation never suspends. If the signer is locked, it fails.
     */
    @Throws(UnlockRequired::class)
    fun sign(data: SignatureInput): CryptoSignature
    fun sign(data: ByteArray) = sign(SignatureInput(data))
}