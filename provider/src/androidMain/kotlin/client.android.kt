package at.asitplus.crypto.provider

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricPrompt.CryptoObject
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.*
import at.asitplus.crypto.datatypes.asn1.Asn1Exception
import at.asitplus.crypto.datatypes.pki.CertificateChain
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import java.security.*
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.util.*
import java.util.concurrent.Executor
import javax.security.auth.x500.X500Principal
import androidx.biometric.BiometricPrompt as BPrompt
import androidx.biometric.BiometricPrompt.PromptInfo as BPinfo


class AndroidPrivateKey(
    val delegate: PrivateKey,
    platformSpecifics: AndroidSpecificCryptoOps,
) :
    CryptoPrivateKey(Platform.Android, platformSpecifics)


internal actual suspend fun clearKey(alias: String, platformSpecifics: PlatformCryptoOpts) = runCatching {
    if (platformSpecifics !is AndroidSpecificCryptoOps) throw InvalidParameterException(
        platformSpecifics,
        "Android requires AndroidSpecificCryptoOps"
    )
    KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }.let {
        it.deleteEntry(alias)
    }
}.wrap()

internal actual suspend fun keyExists(alias: String, platformSpecifics: PlatformCryptoOpts) = runCatching {
    if (platformSpecifics !is AndroidSpecificCryptoOps) throw InvalidParameterException(
        platformSpecifics,
        "Android requires AndroidSpecificCryptoOps"
    )
    KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }.let {
        it.containsAlias(alias)
    }
}.wrap()


internal actual suspend fun doGetKeyPair(
    alias: String,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<CryptoKeyPair> =
    keyExists(alias, platformSpecifics).mapCatching {
        if (!it) throw CryptoObjectNotFoundException("Key $alias does not exist")
        KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }.let {
            AndroidPrivateKey(
                it.getKey(alias, null) as PrivateKey,
                platformSpecifics as AndroidSpecificCryptoOps,
            ) to CryptoPublicKey.fromJcaPublicKey(it.getCertificateChain(alias).first().publicKey)
                .getOrThrow() as CryptoPublicKey.EC
        }
    }
        .mapFailure {
            if (it is Asn1Exception || it is CertificateException) EncodingException(
                it.message,
                it
            ) else it
        }/*this cast is not really necessary, but the compiler gets confused by mapCatching*/ as KmmResult<CryptoKeyPair>


internal actual suspend fun createKey(
    alias: String,
    cryptoAlgorithm: CryptoAlgorithm,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<CryptoKeyPair> = runCatching {
    if (platformSpecifics !is AndroidSpecificCryptoOps) throw InvalidParameterException(
        platformSpecifics,
        "Android requires AndroidSpecificCryptoOps"
    )
    val kp =
        generateKeyPair(
            alias,
            null,
            Clock.System.now(),
            cryptoAlgorithm,
            platformSpecifics
        )
    val pubKey = kp.public as ECPublicKey
    AndroidPrivateKey(kp.private, platformSpecifics) to (CryptoPublicKey.EC.fromJcaPublicKey(pubKey)
        .getOrThrow() as CryptoPublicKey.EC)
}.wrap()

class AndroidSpecificCryptoOps(
    vararg val purposes: Int = arrayOf(0).toIntArray(),
    val keyGenCustomization: KeyGenParameterSpec.Builder.() -> Unit = {},
    onNotAuthenticated: (UserNotAuthenticatedException.(cryptoObject: CryptoObject?) -> BiometricAuth)? = null
) : PlatformCryptoOpts {

    var onNotAuthenticated: (UserNotAuthenticatedException.(cryptoObject: CryptoObject?) -> BiometricAuth)? =
        onNotAuthenticated
        private set

    fun attachAuthenticationHandler(handler: (UserNotAuthenticatedException.(cryptoObject: CryptoObject?) -> BiometricAuth)) {
        onNotAuthenticated = handler
    }

    class BiometricAuth(
        val promptInfo: BPinfo,
        val biometricPrompt: BiometricPromptAdapter
    ) {
        sealed class AuthResult {
            class Success(val result: BPrompt.AuthenticationResult) : AuthResult()
            class Error(val errorCode: Int, val errString: CharSequence) : AuthResult()
            class Failure() : AuthResult()
        }
    }
}


class BiometricPromptAdapter private constructor(
    activity: FragmentActivity?,
    fragment: Fragment?,
    val executor: Executor
) {

    constructor(fragment: Fragment, executor: Executor) : this(null, fragment, executor)
    constructor(fragmentActivity: FragmentActivity, executor: Executor) : this(fragmentActivity, null, executor)

    val callback = AuthnCallback()
    private val bPrompt: BPrompt

    init {

        val callbackSiphon = object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                CoroutineScope(executor.asCoroutineDispatcher()).launch { callback.onAuthError(errorCode, errString) }
            }

            override fun onAuthenticationFailed() {
                CoroutineScope(executor.asCoroutineDispatcher()).launch { callback.onAutheFailed() }
            }

            override fun onAuthenticationSucceeded(result: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                CoroutineScope(executor.asCoroutineDispatcher()).launch { callback.onAuthSucceeded(result) }
            }
        }

        bPrompt = if (fragment != null)
            BPrompt(fragment, executor, callbackSiphon)
        else BPrompt(activity!!, executor, callbackSiphon)

    }


    suspend fun authenticate(promptInfo: BPinfo, cryptoObject: BPrompt.CryptoObject?) {
        cryptoObject?.also { bPrompt.authenticate(promptInfo, cryptoObject) } ?: bPrompt.authenticate(promptInfo)

    }


    class AuthnCallback {
        val callbackChannel =
            Channel<AndroidSpecificCryptoOps.BiometricAuth.AuthResult>(capacity = Channel.RENDEZVOUS)

        internal suspend fun onAuthError(errorCode: Int, errString: CharSequence) {
            callbackChannel.send(
                AndroidSpecificCryptoOps.BiometricAuth.AuthResult.Error(
                    errorCode,
                    errString
                )
            )
        }


        internal suspend fun onAuthSucceeded(result: BPrompt.AuthenticationResult) {
            callbackChannel.send(
                AndroidSpecificCryptoOps.BiometricAuth.AuthResult.Success(result)
            )
        }

        internal suspend fun onAutheFailed() {
            callbackChannel.send(AndroidSpecificCryptoOps.BiometricAuth.AuthResult.Failure())
        }
    }
}


internal actual suspend fun createAttestedP256Key(
    alias: String,
    attestationChallenge: ByteArray,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<TbaKey> = runCatching {
    if (platformSpecifics !is AndroidSpecificCryptoOps) throw InvalidParameterException(
        platformSpecifics,
        "Android requires AndroidSpecificCryptoOps"
    )
    val kp =
        generateKeyPair(
            alias,
            attestationChallenge,
            Clock.System.now(),
            CryptoAlgorithm.ES256,
            platformSpecifics
        )

    val pubKey = kp.public as ECPublicKey
    val proof = loadCertChain(alias)!!.map { it.encoded }
    CryptoPublicKey.EC.fromJcaPublicKey(pubKey)
        .map {
            (AndroidPrivateKey(
                kp.private,
                platformSpecifics,
            ) to (it as CryptoPublicKey.EC)) to proof
        }.getOrThrow()
}.wrap()

private fun generateKeyPair(
    alias: String,
    challenge: ByteArray?,
    validFrom: Instant,
    cryptoAlgorithm: CryptoAlgorithm,
    platformSpecifics: AndroidSpecificCryptoOps
): java.security.KeyPair {
    val builder = KeyGenParameterSpec.Builder(//
        alias,
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or platformSpecifics.purposes.reduce { acc, keyProperties -> acc or keyProperties } //for consistency with iOS
    ).setKeySize(
        when (cryptoAlgorithm) {
            CryptoAlgorithm.ES256 -> 256
            CryptoAlgorithm.ES384 -> 384
            CryptoAlgorithm.ES512 -> 521
            else -> throw UnsupportedAlgorithmException(cryptoAlgorithm, "Illegal Algorithm: $cryptoAlgorithm")
        }
    ).setDigests(
        "SHA-${cryptoAlgorithm.name.takeLast(3).toInt()}",
    )
        .setCertificateNotBefore(Date(validFrom.toEpochMilliseconds())) //valid since now
        .setCertificateSubject(X500Principal("CN=$alias")) //depending on the android version this is ignored anyway
    platformSpecifics.keyGenCustomization.invoke(builder)
    challenge?.apply { builder.setAttestationChallenge(this) } // this is crucial, in order to generate a certificate with attestation extensions


    val keyGenParameterSpec = builder.build()
    val keyPairGenerator: KeyPairGenerator = //let's roll
        KeyPairGenerator.getInstance("EC", "AndroidKeyStore").apply {
            initialize(keyGenParameterSpec)
        }
    return keyPairGenerator.generateKeyPair()
}

private fun loadCertChain(alias: String): List<X509Certificate>? =
    KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }.let {
        it.getCertificateChain(alias)?.map { it as X509Certificate }
    }

internal actual suspend fun signData(
    data: ByteArray,
    signingKey: CryptoPrivateKey,
    algorithm: CryptoAlgorithm
): KmmResult<CryptoSignature> =
    runCatching {
        if (signingKey !is AndroidPrivateKey) throw InvalidParameterException(
            signingKey.platformSpecifics,
            "Android requires AndroidSigningKey"
        )
        val platformSpecifics = signingKey.platformSpecifics
        if (platformSpecifics !is AndroidSpecificCryptoOps) throw InvalidParameterException(
            platformSpecifics,
            "Android requires AndroidSpecificCryptoOps"
        )
        val signerKey = signingKey.delegate

        var sig = Signature.getInstance(algorithm.jcaName)
        var result: ByteArray? = null


        //this happens with a timeout
        runCatching { sig.initSign(signerKey) }.onFailure {
            if (it is UserNotAuthenticatedException) platformSpecifics.onNotAuthenticated?.invoke(it, null)?.let {
                CoroutineScope(it.biometricPrompt.executor.asCoroutineDispatcher()).launch {
                    it.biometricPrompt.authenticate(it.promptInfo, null)
                }

                val res = it.biometricPrompt.callback.callbackChannel.receive()

                when (res) {
                    is AndroidSpecificCryptoOps.BiometricAuth.AuthResult.Failure -> {
                        throw AuthenticationException("Auth Failure")
                    }

                    is AndroidSpecificCryptoOps.BiometricAuth.AuthResult.Error -> {
                        throw AuthenticationException("Auth Error: ${res.errorCode}: ${res.errString}")
                    }

                    is AndroidSpecificCryptoOps.BiometricAuth.AuthResult.Success -> {
                        sig.initSign(signerKey)
                    }
                }
            }
            else throw it
        }

        val factory: KeyFactory = KeyFactory.getInstance(signerKey.algorithm, "AndroidKeyStore")
        val keyInfo = factory.getKeySpec(signerKey, KeyInfo::class.java)

        if (keyInfo.isUserAuthenticationRequired && keyInfo.userAuthenticationValidityDurationSeconds == 0) {
            val cryptoObject = CryptoObject(sig)

            platformSpecifics.onNotAuthenticated?.invoke(
                UserNotAuthenticatedException("Auth-per-use key"),
                cryptoObject
            )?.let {
                CoroutineScope(it.biometricPrompt.executor.asCoroutineDispatcher()).launch {
                    it.biometricPrompt.authenticate(it.promptInfo, cryptoObject)
                }
                val res = it.biometricPrompt.callback.callbackChannel.receive()

                when (res) {
                    is AndroidSpecificCryptoOps.BiometricAuth.AuthResult.Failure -> {
                        throw AuthenticationException("Auth Failure")
                    }

                    is AndroidSpecificCryptoOps.BiometricAuth.AuthResult.Error -> {
                        throw AuthenticationException("Auth Error: ${res.errorCode}: ${res.errString}")
                    }

                    is AndroidSpecificCryptoOps.BiometricAuth.AuthResult.Success -> {
                        sig = cryptoObject.signature!!
                    }
                }
            }
        }
        sig.apply {
            update(data)
            result = sign()
        }
        result

    }.mapCatching { CryptoSignature.decodeFromDer(it!!) }.wrap()


internal actual suspend fun doVerify(
    algorithm: CryptoAlgorithm,
    publicKey: CryptoPublicKey.EC,
    data: ByteArray,
    detachedSignature: CryptoSignature
): KmmResult<Boolean> =
    runCatching {
        Signature.getInstance(algorithm.jcaName).let {
            it.initVerify(publicKey.getJcaPublicKey().getOrThrow())
            it.update(data)
            it.verify(detachedSignature.jcaSignatureBytes)
        }
    }.wrap()


internal actual suspend fun doGetPublicKey(
    alias: String,
    platformSpecifics: PlatformCryptoOpts?
): KmmResult<CryptoPublicKey> {
    if (platformSpecifics != null && platformSpecifics !is AndroidSpecificCryptoOps) throw InvalidParameterException(
        platformSpecifics,
        "AndroidSpecificCryptoOps required!"
    )
    KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }.let {
        return runCatching {
            CryptoPublicKey.fromJcaPublicKey(it.getCertificateChain(alias).first().publicKey).getOrThrow()
        }.wrap()
    }
}

internal actual suspend fun doStoreCertificateChain(
    alias: String,
    certs: CertificateChain,
    platformSpecifics: PlatformCryptoOpts?
): KmmResult<Unit> = runCatching {
    val builder = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    ).setKeySize(
        256
    ).setDigests(
        "SHA-256",
    )
        .setCertificateNotBefore(Date(Clock.System.now().toEpochMilliseconds())) //valid since now
        .setCertificateSubject(X500Principal("CN=$alias")) //depending on the android version this is ignored anyway


    val keyGenParameterSpec = builder.build()
    val keyPairGenerator: KeyPairGenerator = //let's roll
        KeyPairGenerator.getInstance("EC", "AndroidKeyStore").apply {
            initialize(keyGenParameterSpec)
        }

    val kP = keyPairGenerator.generateKeyPair()

    KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }.let {
        it.setKeyEntry(
            alias,
            kP.private,
            null,
            certs.map { it.toJcaCertificate().getOrThrow() }.toTypedArray()
        )
    }
}.wrap()

internal actual suspend fun doGetCertificateChain(
    alias: String,
    platformSpecifics: PlatformCryptoOpts?
): KmmResult<CertificateChain> = runCatching {
    KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }.let {
        it.getCertificateChain(alias).map { at.asitplus.crypto.datatypes.pki.X509Certificate.decodeFromDer(it.encoded) }
    }
}.wrap()
