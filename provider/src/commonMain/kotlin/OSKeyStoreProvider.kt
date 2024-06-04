package at.asitplus.crypto.provider

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.provider.sign.Signer
import com.ionspin.kotlin.bignum.integer.BigInteger

class UnlockRequired(cause: Throwable?): Exception(cause)
class UnlockFailed(message: String): Exception(message)

open class SigningKeyConfiguration internal constructor(): DSL.Data() {
    open class AttestationConfiguration: DSL.Data() {
        var challenge: ByteArray? = null
        override fun validate() {
            require(challenge != null) { "Server-provided attestation challenge must be set" }
        }
    }
    open val attestation = childOrNull(::AttestationConfiguration)

    sealed class AlgorithmSpecific: DSL.Data()
    internal val _algSpecific = subclassOf<AlgorithmSpecific>(default = ECConfiguration())
    open class RSAConfiguration: AlgorithmSpecific()
    {
        companion object { val F0 = BigInteger(3); val F4 = BigInteger(65537)}
        var bits: Int = 4096
        var publicExponent: BigInteger = F4
    }
    open val rsa = _algSpecific.option(::RSAConfiguration)
    open class ECConfiguration: AlgorithmSpecific() { var curve: ECCurve = ECCurve.SECP_256_R_1 }
    open val ec = _algSpecific.option(::ECConfiguration)

    var digest = Digest.SHA256
}

open class SignerConfiguration internal constructor() : DSL.Data() {
    open class AuthnPrompt: DSL.Data() {
        var message: String = "Please authorize cryptographic signature"
        var cancelText: String = "Abort"
    }
    open val unlockPrompt = child(::AuthnPrompt)
}

interface OSSigningKeyStoreI<out PlatformSigningKeyConfiguration: SigningKeyConfiguration, out PlatformSignerConfiguration: SignerConfiguration> {
    fun createSigningKey(alias: String, configure: (PlatformSigningKeyConfiguration.()->Unit)? = null): CryptoPublicKey
    fun hasSigningKey(alias: String): Boolean
    fun getSignerForKey(alias: String, configure: (PlatformSignerConfiguration.()->Unit)? = null): Signer
    fun deleteSigningKey(alias: String): Unit
}
typealias OSSignerProvider = OSSigningKeyStoreI<*,*>
