package at.asitplus.crypto.provider.os

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.provider.dsl.DSL
import at.asitplus.crypto.provider.dsl.DSLConfigureFn
import at.asitplus.crypto.provider.sign.Signer
import com.ionspin.kotlin.bignum.integer.BigInteger

open class SigningKeyConfiguration internal constructor(): DSL.Data() {
    sealed class AlgorithmSpecific: DSL.Data()
    internal val _algSpecific = subclassOf<AlgorithmSpecific>(default = ECConfiguration())
    open class ECConfiguration internal constructor() : AlgorithmSpecific() {
        var digest: Digest = Digest.SHA256
        var curve : ECCurve = ECCurve.SECP_256_R_1
    }
    open val ec = _algSpecific.option(::ECConfiguration)

    open class RSAConfiguration internal constructor(): AlgorithmSpecific() {
        companion object { val F0 = BigInteger(3); val F4 = BigInteger(65537)}
        var digest: Digest = Digest.SHA256
        var bits: Int = 4096
        var publicExponent: BigInteger = F4
    }
    open val rsa = _algSpecific.option(::RSAConfiguration)
}

open class PlatformSigningKeyConfiguration<PlatformSignerConfiguration: SignerConfiguration> internal constructor(): SigningKeyConfiguration() {
    open class AttestationConfiguration: DSL.Data() {
        /** The server-provided attestation challenge */
        lateinit var challenge: ByteArray
        override fun validate() {
            require(this::challenge.isInitialized) { "Server-provided attestation challenge must be set" }
        }
    }
    open val attestation = childOrNull(::AttestationConfiguration)

    open val signer = integratedReceiver<PlatformSignerConfiguration>()
}

open class SignerConfiguration internal constructor(): DSL.Data() {
    open class AuthnPrompt: DSL.Data() {
        /** The prompt message to show to the user when asking for unlock */
        var message: String = "Please authorize cryptographic signature"
        /** The message to show on the cancellation button */
        var cancelText: String = "Abort"
    }
    open val unlockPrompt = child(::AuthnPrompt)
}

interface TPMSigningProviderI<out SignerT: Signer,
        out SignerConfigT: SignerConfiguration,
        out KeyConfigT: PlatformSigningKeyConfiguration<*>> {
    fun createSigningKey(alias: String, configure: DSLConfigureFn<KeyConfigT> = null) : KmmResult<SignerT>
    fun getSignerForKey(alias: String, configure: DSLConfigureFn<SignerConfigT> = null) : KmmResult<SignerT>
    fun deleteSigningKey(alias: String)
}
typealias TPMSigningProvider = TPMSigningProviderI<*,*,*>
