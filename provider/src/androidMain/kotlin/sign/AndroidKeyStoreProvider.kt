package at.asitplus.crypto.provider.sign

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
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.fromJcaPublicKey
import at.asitplus.crypto.datatypes.jcaName
import at.asitplus.crypto.datatypes.pki.CertificateChain
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.datatypes.pki.leaf
import at.asitplus.crypto.provider.DSL
import at.asitplus.crypto.provider.OSSigningKeyStoreI
import at.asitplus.crypto.provider.SignerConfiguration
import at.asitplus.crypto.provider.SigningKeyConfiguration
import at.asitplus.crypto.provider.UnlockFailed
import at.asitplus.crypto.provider.UnlockRequired
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import kotlinx.coroutines.CoroutineScope
import at.asitplus.crypto.provider.sign.Signer as SignerI
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
import javax.security.auth.x500.X500Principal

private sealed interface FragmentContext {
    @JvmInline value class OfActivity(val activity: FragmentActivity): FragmentContext
    @JvmInline value class OfFragment(val fragment: Fragment): FragmentContext
}

class AndroidSigningKeyConfiguration: SigningKeyConfiguration()

class AndroidSignerConfiguration: SignerConfiguration() {
    open class AuthnPrompt: SignerConfiguration.AuthnPrompt() {
        var subtitle: String? = null
        var description: String? = null
        var confirmationRequired: Boolean? = null
        var allowedAuthenticators: Int? = null
    }
    override val unlockPrompt = child(::AuthnPrompt)
}

class AndroidKeyStoreProvider private constructor(
    private val context: FragmentContext):
    OSSigningKeyStoreI<AndroidSigningKeyConfiguration, AndroidSignerConfiguration> {

    constructor(activity: FragmentActivity) : this(FragmentContext.OfActivity(activity))
    constructor(fragment: Fragment): this(FragmentContext.OfFragment(fragment))

    private val executor = when (context) {
        is FragmentContext.OfActivity -> ContextCompat.getMainExecutor(context.activity)
        is FragmentContext.OfFragment -> ContextCompat.getMainExecutor(context.fragment.context)
    }

    private val ks: KeyStore =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }

    private sealed interface AuthResult {
        @JvmInline value class Success(val result: AuthenticationResult): AuthResult
        data class Error(val code: Int, val message: String): AuthResult
    }
    private suspend fun attemptBiometry(config: AndroidSignerConfiguration.AuthnPrompt, forSpecificKey: CryptoObject?) {
        val channel = Channel<AuthResult>(capacity = Channel.RENDEZVOUS)
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

    inner class Signer internal constructor(val alias: String, val config: AndroidSignerConfiguration): SignerI {
        private val jcaPrivateKey = ks.getKey(alias, null) as PrivateKey
        override val publicKey get() = certificateChain.leaf.publicKey
        override val certificateChain: CertificateChain by lazy {
            ks.getCertificateChain(alias).map { X509Certificate.decodeFromDer(it.encoded) }
        }

        val keyInfo = KeyFactory.getInstance(jcaPrivateKey.algorithm, "AndroidKeyStore")
            .getKeySpec(jcaPrivateKey, KeyInfo::class.java)

        val needsAuthentication inline get() =
            keyInfo.isUserAuthenticationRequired
        val needsAuthenticationForEveryUse inline get() =
            keyInfo.isUserAuthenticationRequired &&
                    (keyInfo.userAuthenticationValidityDurationSeconds <= 0)
        val needsAuthenticationWithTimeout inline get() =
            keyInfo.isUserAuthenticationRequired &&
                    (keyInfo.userAuthenticationValidityDurationSeconds > 0)

        override suspend fun unlock() {
            if (!needsAuthentication) return
            if (needsAuthenticationForEveryUse) {
                throw UnsupportedOperationException("Must be authorized once per use")
            }
            attemptBiometry(config.unlockPrompt.v, null)
        }

        override fun sign(data: SignatureInput): CryptoSignature =
            Signature.getInstance(jcaPrivateKey.algorithm).runCatching {
                initSign(jcaPrivateKey)
                data.data.forEach(this::update)
                sign()
            }.getOrElse {
                when (it) {
                    is UserNotAuthenticatedException -> throw UnlockRequired(it)
                    else -> throw it
                }
            }.let(CryptoSignature::decodeFromDer)

        override suspend fun unlockAndSign(data: SignatureInput): CryptoSignature =
            Signature.getInstance(jcaPrivateKey.algorithm).let {
                if (needsAuthenticationForEveryUse) {
                    /* authentication before use */
                    it.initSign(jcaPrivateKey)
                    val o = CryptoObject(it)
                    attemptBiometry(config.unlockPrompt.v, o)
                    o.signature!!
                } else try {
                    /* try using it without authenticating */
                    it.initSign(jcaPrivateKey)
                    it
                } catch (_: UserNotAuthenticatedException) {
                    /* authenticate if a timeout is thrown */
                    attemptBiometry(config.unlockPrompt.v, null)
                    it.initSign(jcaPrivateKey)
                    it
                }
            }.run {
                data.data.forEach(this::update)
                sign()
            }.let(CryptoSignature::decodeFromDer)
    }

    override fun createSigningKey(
        alias: String,
        configure: (AndroidSigningKeyConfiguration.() -> Unit)?
    ): CryptoPublicKey {
        val config = DSL.resolve(::AndroidSigningKeyConfiguration, configure)

        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN
        ).apply {
            setAlgorithmParameterSpec(when(val algSpec = config._algSpecific.v) {
                is SigningKeyConfiguration.RSAConfiguration ->
                    RSAKeyGenParameterSpec(algSpec.bits, algSpec.publicExponent.toJavaBigInteger())
                is SigningKeyConfiguration.ECConfiguration ->
                    ECGenParameterSpec(algSpec.curve.jcaName)
            })
            setDigests(config.digest.jcaName)
            //setCertificateNotBefore() TODO
            setCertificateSubject(X500Principal("CN=$alias")) // TODO
            config.attestation.v?.let {
                setAttestationChallenge(it.challenge!!)
            }
        }.build()
        val keypair = KeyPairGenerator.getInstance(when(config._algSpecific.v) {
            is SigningKeyConfiguration.RSAConfiguration -> "RSA"
            is SigningKeyConfiguration.ECConfiguration -> "EC"
        }, "AndroidKeyStore").apply {
            initialize(spec)
        }.generateKeyPair()
        return CryptoPublicKey.fromJcaPublicKey(keypair.public).getOrThrow()
    }

    override fun hasSigningKey(alias: String) = ks.containsAlias(alias)

    override fun getSignerForKey(alias: String, configure: (AndroidSignerConfiguration.()->Unit)?) =
        Signer(alias, DSL.resolve(::AndroidSignerConfiguration, configure))
    override fun deleteSigningKey(alias: String) {
        TODO("Not yet implemented")
    }
}