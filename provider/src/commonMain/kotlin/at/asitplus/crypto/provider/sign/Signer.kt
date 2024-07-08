package at.asitplus.crypto.provider.sign

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.SignatureAlgorithm

sealed interface Signer {
    val signatureAlgorithm: SignatureAlgorithm
    val publicKey: CryptoPublicKey


    /** Any [Signer] instantiation must be [EC] or [RSA] */
    sealed interface AlgTrait : Signer

    /** ECDSA signer */
    interface EC : Signer.AlgTrait {
        override val signatureAlgorithm: SignatureAlgorithm.ECDSA
        override val publicKey: CryptoPublicKey.EC
    }

    /** RSA signer */
    interface RSA : Signer.AlgTrait

    /** Any [Signer] is either [Unlocked] or [Unlockable] */
    sealed interface UnlockTrait: Signer

    /**
     * This signer either does not require unlock, or is already unlocked.
     * Signing operations immediately complete.
     */
    interface Unlocked: Signer.UnlockTrait {
        /**
         * Signs the input.
         * This operation never suspends.
         */
        fun sign(data: SignatureInput): KmmResult<CryptoSignature>
    }

    /**
     * This signer might require unlock.
     * Signing operations might suspend while the user is prompted for confirmation.
     *
     * Some signers of this type are [TemporarilyUnlockable].
     */
    interface Unlockable: Signer.UnlockTrait {
        /**
         * Unlocks this signer, and signs the message once unlocked.
         * This operation might suspend and request unlock from the user.
         */
        suspend fun sign(data: SignatureInput): KmmResult<CryptoSignature>
    }

    /**
     * A handle to a [TemporarilyUnlockable] signer that is temporarily unlocked.
     * The handle is only guaranteed to be valid within the scope of the block.
     */
    @OptIn(ExperimentalStdlibApi::class)
    interface UnlockedHandle: AutoCloseable, Signer.Unlocked

    /**
     * An [Unlockable] signer that can be temporarily unlocked.
     * Once unlocked, multiple signing operations can be performed with a single unlock.
     */
    abstract class TemporarilyUnlockable<Handle: UnlockedHandle> : Signer.Unlockable {
        protected abstract suspend fun unlock(): KmmResult<Handle>

        /**
         * Unlocks the signer, then executes the block with the [UnlockedHandle] as its receiver.
         *
         * The handle's validity is only guaranteed in the block scope.
         */
        @OptIn(ExperimentalStdlibApi::class)
        suspend fun <T> withUnlock(fn: Handle.()->T): KmmResult<T> =
            unlock().mapCatching { it.use(fn) }

        final override suspend fun sign(data: SignatureInput): KmmResult<CryptoSignature> =
            withUnlock { sign(data).getOrThrow() }
    }
}

val Signer.EC.curve get() = publicKey.curve

/** Sign without caring what type of signer this is. Might suspend. */
suspend fun Signer.sign(data: SignatureInput): KmmResult<CryptoSignature> {
    this as Signer.UnlockTrait
    return when (this) {
        is Signer.Unlocked -> sign(data)
        is Signer.Unlockable -> sign(data)
    }
}

suspend inline fun Signer.sign(data: ByteArray) = sign(SignatureInput(data))
inline fun Signer.Unlocked.sign(data: ByteArray) = sign(SignatureInput(data))
suspend inline fun Signer.Unlockable.sign(data: ByteArray) = sign(SignatureInput(data))
