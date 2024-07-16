package at.asitplus.crypto.provider.os

import android.annotation.SuppressLint
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.AuthenticationResult
import androidx.biometric.BiometricPrompt.CryptoObject
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.RSAPadding
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.datatypes.getJCASignatureInstance
import at.asitplus.crypto.datatypes.jcaName
import at.asitplus.crypto.datatypes.parseFromJca
import at.asitplus.crypto.datatypes.pki.CertificateChain
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.datatypes.pki.leaf
import at.asitplus.crypto.provider.UnlockFailed
import at.asitplus.crypto.provider.UnsupportedCryptoException
import at.asitplus.crypto.provider.dsl.DSL
import at.asitplus.crypto.provider.dsl.DSLConfigureFn
import at.asitplus.crypto.provider.sign.SignatureInput
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import at.asitplus.crypto.provider.sign.Signer as SignerI
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.time.Instant
import java.util.Date
import javax.security.auth.x500.X500Principal
import kotlin.enums.enumEntries
import java.security.Signature as JCASignatureObject

internal sealed interface FragmentContext {
    @JvmInline value class OfActivity(val activity: FragmentActivity): FragmentContext
    @JvmInline value class OfFragment(val fragment: Fragment): FragmentContext
}


class AndroidTPMConfiguration internal constructor(): PlatformSigningKeyConfiguration.TPMConfiguration() {
    /** Whether a StrongBox TPM is required. */
    var requireStrongBox = false
}
class AndroidSigningKeyConfiguration internal constructor(): PlatformSigningKeyConfiguration<AndroidSignerConfiguration>() {
    override val tpm = childOrNull(::AndroidTPMConfiguration)
}

class AndroidSignerConfiguration: SignerConfiguration() {
    class AuthnPrompt: SignerConfiguration.AuthnPrompt() {
        var subtitle: String? = null
        var description: String? = null
        var confirmationRequired: Boolean? = null
        var allowedAuthenticators: Int? = null
        /** if the provided fingerprint could not be matched, but the user will be allowed to retry */
        var invalidBiometryCallback: (()->Unit)? = null
    }
    override val unlockPrompt = child(::AuthnPrompt)
}

/**
 * Resolve [what] differently based on whether the [v]alue was [spec]ified.
 *
 * * [spec] = `true`: Check if [valid] contains [nameMap] applied to [v], return [v] if yes, throw otherwise
 * * [spec] = `false`: Check if [valid] contains exactly one element, if yes, return the [E] from [possible] for which [nameMap] returns that element, throw otherwise
 */
inline fun <reified E> resolveOption(what: String, valid: Array<String>, possible: Sequence<E>, spec: Boolean, v: E, crossinline nameMap: (E)->String): E =
    when (spec) {
        true -> {
            val vStr = nameMap(v)
            if (!valid.any { it.equals(vStr, ignoreCase=true) })
                throw IllegalArgumentException("Key does not suppport $what $v; supported: $valid")
            v
        }
        false -> {
            if (valid.size != 1)
                throw IllegalArgumentException("Key supports multiple ${what}s ($valid). You need to specify $what in signer configuration.")
            val only = valid.first()
            possible.find {
                nameMap(it).equals(only, ignoreCase=true)
            } ?: throw UnsupportedCryptoException("Unsupported $what $only")
        }
    }

sealed class AndroidKeyStoreProviderImpl<SignerT: AndroidKeystoreSigner> private constructor() :
    TPMSigningProviderI<SignerT, AndroidSignerConfiguration, AndroidSigningKeyConfiguration>
{

    class WithoutContext internal constructor() :
        AndroidKeyStoreProviderImpl<UnlockedAndroidKeystoreSigner>()
    {
        override val context get() = null
    }

    class WithContext internal constructor(override val context: FragmentContext) :
        AndroidKeyStoreProviderImpl<AndroidKeystoreSigner>()

    companion object {
        /**
         * Instantiate the keystore provider without associating an activity or fragment.
         * Biometric authentication will be impossible.
         */
        operator fun invoke() =
            WithoutContext()

        /**
         * Instantiate the keystore provider associated with this particular activity.
         */
        operator fun invoke(activity: FragmentActivity) =
            WithContext(FragmentContext.OfActivity(activity))

        /**
         * Instantiate the keystore provider associated with this particular fragment.
         */
        operator fun invoke(fragment: Fragment) =
            WithContext(FragmentContext.OfFragment(fragment))
    }

    private val ks: KeyStore =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }

    @SuppressLint("WrongConstant")
    final override fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<AndroidSigningKeyConfiguration>
    ) = catching {
        val config = DSL.resolve(::AndroidSigningKeyConfiguration, configure)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN
        ).apply {
            when(val algSpec = config._algSpecific.v) {
                is SigningKeyConfiguration.RSAConfiguration -> {
                    setAlgorithmParameterSpec(
                        RSAKeyGenParameterSpec(algSpec.bits, algSpec.publicExponent.toJavaBigInteger()))
                    setDigests(*algSpec.digests.map(Digest::jcaName).toTypedArray())
                    setSignaturePaddings(*algSpec.paddings.map {
                        when (it) {
                            RSAPadding.PKCS1 -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
                            RSAPadding.PSS -> KeyProperties.SIGNATURE_PADDING_RSA_PSS
                        }
                    }.toTypedArray())
                }
                is SigningKeyConfiguration.ECConfiguration -> {
                    setAlgorithmParameterSpec(ECGenParameterSpec(algSpec.curve.jcaName))
                    setDigests(*algSpec.digests.map { it?.jcaName ?: KeyProperties.DIGEST_NONE }.toTypedArray())
                }
            }
            setCertificateNotBefore(Date.from(Instant.now()))
            setCertificateSubject(X500Principal("CN=$alias")) // TODO
            config.tpm.v?.let { tpm ->
                setIsStrongBoxBacked(tpm.requireStrongBox)
                tpm.attestation.v?.let {
                    setAttestationChallenge(it.challenge)
                }
                tpm.protection.v?.let {
                    setUserAuthenticationRequired(true)
                    setUserAuthenticationParameters(it.timeout.inWholeSeconds.toInt(),
                        (if (it.factors.v.biometry) KeyProperties.AUTH_BIOMETRIC_STRONG else 0) or
                        (if (it.factors.v.deviceLock) KeyProperties.AUTH_DEVICE_CREDENTIAL else 0))
                }
            }
        }.build()
        KeyPairGenerator.getInstance(when(config._algSpecific.v) {
            is SigningKeyConfiguration.RSAConfiguration -> KeyProperties.KEY_ALGORITHM_RSA
            is SigningKeyConfiguration.ECConfiguration -> KeyProperties.KEY_ALGORITHM_EC
        }, "AndroidKeyStore").apply {
            initialize(spec)
        }.generateKeyPair()
        return@catching getSignerForKey(alias, config.signer.v).getOrThrow()
    }

    internal abstract val context: FragmentContext?

    final override fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<AndroidSignerConfiguration>
    ): KmmResult<SignerT> = catching {
        val jcaPrivateKey = ks.getKey(alias, null) as PrivateKey
        val config = DSL.resolve(::AndroidSignerConfiguration, configure)
        val certificateChain =
            ks.getCertificateChain(alias).map { X509Certificate.decodeFromDer(it.encoded) }
        val keyInfo = KeyFactory.getInstance(jcaPrivateKey.algorithm)
            .getKeySpec(jcaPrivateKey, KeyInfo::class.java)
        val algorithm = when (val publicKey = certificateChain.leaf.publicKey) {
            is CryptoPublicKey.EC -> {
                val ecConfig = config.ec.v
                val digest = resolveOption("digest", keyInfo.digests, Digest.entries.asSequence() + sequenceOf<Digest?>(null), ecConfig.digestSpecified, ecConfig.digest) { it?.jcaName ?: KeyProperties.DIGEST_NONE }
                SignatureAlgorithm.ECDSA(digest, publicKey.curve)
            }
            is CryptoPublicKey.Rsa -> {
                val rsaConfig = config.rsa.v
                val digest = resolveOption<Digest>("digest", keyInfo.digests, Digest.entries.asSequence(), rsaConfig.digestSpecified, rsaConfig.digest, Digest::jcaName)
                val padding = resolveOption<RSAPadding>("padding", keyInfo.signaturePaddings, RSAPadding.entries.asSequence(), rsaConfig.paddingSpecified, rsaConfig.padding) {
                    when (it) {
                        RSAPadding.PKCS1 -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
                        RSAPadding.PSS -> KeyProperties.SIGNATURE_PADDING_RSA_PSS
                    }
                }
                SignatureAlgorithm.RSA(digest, padding)
            }
        }

        val result: AndroidKeystoreSigner = if (keyInfo.isUserAuthenticationRequired) {
            val ctx = context
                ?: throw IllegalStateException("Key requires biometric authentication, but no fragment/activity context is available.")
            when (certificateChain.leaf.publicKey) {
                is CryptoPublicKey.EC ->
                    LockedAndroidKeystoreSigner.ECDSA(
                        ctx, jcaPrivateKey, keyInfo, config, certificateChain,
                        algorithm as SignatureAlgorithm.ECDSA)
                is CryptoPublicKey.Rsa ->
                    LockedAndroidKeystoreSigner.RSA(
                        ctx, jcaPrivateKey, keyInfo, config, certificateChain,
                        algorithm as SignatureAlgorithm.RSA)
            }
        } else {
            val jcaSig = algorithm.getJCASignatureInstance(isAndroid=true)
                .getOrThrow().also { it.initSign(jcaPrivateKey) }
            when (val publicKey = certificateChain.leaf.publicKey) {
                is CryptoPublicKey.EC ->
                    UnlockedAndroidKeystoreSigner.ECDSA(
                        jcaSig, keyInfo, certificateChain, publicKey,
                        algorithm as SignatureAlgorithm.ECDSA)
                is CryptoPublicKey.Rsa ->
                    UnlockedAndroidKeystoreSigner.RSA(
                        jcaSig, keyInfo, certificateChain, publicKey,
                        algorithm as SignatureAlgorithm.RSA)
            }
        }
        @Suppress("UNCHECKED_CAST")
        return@catching result as SignerT
    }

    final override fun deleteSigningKey(alias: String) {
        ks.deleteEntry(alias)
    }
}

typealias AndroidKeyStoreProvider = AndroidKeyStoreProviderImpl<*>

interface AndroidKeystoreSigner : SignerI.Attested {
    val keyInfo: KeyInfo
}

sealed class UnlockedAndroidKeystoreSigner private constructor(
    private val jcaSig: JCASignatureObject,
    override val keyInfo: KeyInfo,
    override val certificateChain: CertificateChain
): SignerI.UnlockedHandle, AndroidKeystoreSigner {

    class ECDSA internal constructor(jcaSig: JCASignatureObject,
                                     keyInfo: KeyInfo,
                                     certificateChain: CertificateChain,
                                     override val publicKey: CryptoPublicKey.EC,
                                     override val signatureAlgorithm: SignatureAlgorithm.ECDSA
    ) : UnlockedAndroidKeystoreSigner(jcaSig, keyInfo, certificateChain), SignerI.ECDSA

    class RSA internal constructor(jcaSig: JCASignatureObject,
                                   keyInfo: KeyInfo,
                                   certificateChain: CertificateChain,
                                   override val publicKey: CryptoPublicKey.Rsa,
                                   override val signatureAlgorithm: SignatureAlgorithm.RSA
    ) : UnlockedAndroidKeystoreSigner(jcaSig, keyInfo, certificateChain), SignerI.RSA

    final override fun sign(data: SignatureInput) = catching {
        require(data.format == null)
        data.data.forEach(jcaSig::update)
        val jcaSignature = jcaSig.sign()
        when (this) {
            is ECDSA -> CryptoSignature.EC.parseFromJca(jcaSignature)
            is RSA -> CryptoSignature.RSAorHMAC.parseFromJca(jcaSignature)
        }
    }

    final override fun close() {}

}

sealed class LockedAndroidKeystoreSigner private constructor(
    private val context: FragmentContext,
    private val jcaPrivateKey: PrivateKey,
    override val keyInfo: KeyInfo,
    private val config: AndroidSignerConfiguration,
    override val certificateChain: CertificateChain
) : SignerI.TemporarilyUnlockable<UnlockedAndroidKeystoreSigner>(), AndroidKeystoreSigner {

    private sealed interface AuthResult {
        @JvmInline value class Success(val result: AuthenticationResult): AuthResult
        data class Error(val code: Int, val message: String): AuthResult
    }

    private suspend fun attemptBiometry(config: AndroidSignerConfiguration.AuthnPrompt, forSpecificKey: CryptoObject?) {
        val channel = Channel<AuthResult>(capacity = Channel.RENDEZVOUS)
        val executor = when (context) {
            is FragmentContext.OfActivity -> ContextCompat.getMainExecutor(context.activity)
            is FragmentContext.OfFragment -> ContextCompat.getMainExecutor(context.fragment.context)
        }
        executor.asCoroutineDispatcher().let(::CoroutineScope).launch {
            val promptInfo = BiometricPrompt.PromptInfo.Builder().apply {
                setTitle(config.message)
                setNegativeButtonText(config.cancelText)
                config.subtitle?.let(this::setSubtitle)
                config.description?.let(this::setDescription)
                config.allowedAuthenticators?.let(this::setAllowedAuthenticators)
                config.confirmationRequired?.let(this::setConfirmationRequired)
            }.build()
            val siphon = object: BiometricPrompt.AuthenticationCallback() {
                private fun send(v: AuthResult) {
                    executor.asCoroutineDispatcher().let(::CoroutineScope).launch { channel.send(v) }
                }
                override fun onAuthenticationSucceeded(result: AuthenticationResult) {
                    send(AuthResult.Success(result))
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    send(AuthResult.Error(errorCode, errString.toString()))
                }
                override fun onAuthenticationFailed() {
                    config.invalidBiometryCallback?.invoke()
                }
            }
            val prompt = when (context) {
                is FragmentContext.OfActivity -> BiometricPrompt(context.activity, executor, siphon)
                is FragmentContext.OfFragment -> BiometricPrompt(context.fragment, executor, siphon)
            }
            when (forSpecificKey) {
                null -> prompt.authenticate(promptInfo)
                else -> prompt.authenticate(promptInfo, forSpecificKey)
            }
        }
        when (val result = channel.receive()) {
            is AuthResult.Success -> return
            is AuthResult.Error -> throw UnlockFailed("${result.message} (code ${result.code})")
        }
    }

    protected abstract fun toUnlocked(jcaSig: JCASignatureObject): UnlockedAndroidKeystoreSigner

    final override suspend fun unlock(): KmmResult<UnlockedAndroidKeystoreSigner> =
        signatureAlgorithm.getJCASignatureInstance(isAndroid=true).onSuccess {
            if (needsAuthenticationForEveryUse) {
                it.initSign(jcaPrivateKey)
                attemptBiometry(config.unlockPrompt.v, CryptoObject(it))
            } else {
                try {
                    it.initSign(jcaPrivateKey)
                } catch (_: UserNotAuthenticatedException) {
                    attemptBiometry(config.unlockPrompt.v, null)
                    it.initSign(jcaPrivateKey)
                }
            }
        }.mapCatching(this::toUnlocked)

    class ECDSA internal constructor(context: FragmentContext,
                                     jcaPrivateKey: PrivateKey,
                                     keyInfo: KeyInfo,
                                     config: AndroidSignerConfiguration,
                                     certificateChain: CertificateChain,
                                     override val signatureAlgorithm: SignatureAlgorithm.ECDSA)
        : LockedAndroidKeystoreSigner(context, jcaPrivateKey, keyInfo, config, certificateChain), SignerI.ECDSA {
        override val publicKey = certificateChain.leaf.publicKey as CryptoPublicKey.EC
        override fun toUnlocked(jcaSig: Signature) =
            UnlockedAndroidKeystoreSigner.ECDSA(jcaSig, keyInfo, certificateChain, publicKey, signatureAlgorithm)
    }

    class RSA internal constructor(context: FragmentContext,
                                   jcaPrivateKey: PrivateKey,
                                   keyInfo: KeyInfo,
                                   config: AndroidSignerConfiguration,
                                   certificateChain: CertificateChain,
                                   override val signatureAlgorithm: SignatureAlgorithm.RSA)
        : LockedAndroidKeystoreSigner(context, jcaPrivateKey, keyInfo, config, certificateChain), SignerI.RSA {
        override val publicKey = certificateChain.leaf.publicKey as CryptoPublicKey.Rsa
        override fun toUnlocked(jcaSig: Signature) =
            UnlockedAndroidKeystoreSigner.RSA(jcaSig, keyInfo, certificateChain, publicKey, signatureAlgorithm)
    }
}

val AndroidKeystoreSigner.needsAuthentication inline get() =
    keyInfo.isUserAuthenticationRequired
val AndroidKeystoreSigner.needsAuthenticationForEveryUse inline get() =
    keyInfo.isUserAuthenticationRequired &&
            (keyInfo.userAuthenticationValidityDurationSeconds <= 0)
val AndroidKeystoreSigner.needsAuthenticationWithTimeout inline get() =
    keyInfo.isUserAuthenticationRequired &&
            (keyInfo.userAuthenticationValidityDurationSeconds > 0)
