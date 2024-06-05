package at.asitplus.crypto.provider

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.pki.CertificateChain

/**
 * Indicates the platform a [CryptoPrivateKey] belongs to.
 */
enum class Platform {
    Jvm,
    Android,
    iOS
}

/**
 * **T**o **b**e **a**ttested Key. Contains a key pair and an attestation proof
 */
typealias TbaKey = Pair<CryptoKeyPair, List<ByteArray>>

val TbaKey.keyPair get() = first
val TbaKey.proof get() = second

/**
 * Representation of a private key. On Android and iOS it contains only a reference to the key stored in the KeyStore/Keychain.
 * the [platformSpecifics] are stateful (e.g. for authentication purposes).
 * [additionalData] can be used to attach arbitrary information to a private key (may also be used for authentication purposes, for example)
 */
abstract class CryptoPrivateKey(val platform: Platform, var platformSpecifics: PlatformCryptoOpts) {
    val additionalData = mutableMapOf<String, Any>()

    override fun toString() = "${this::class.simpleName}"
}

/**
 * Nomen est omen. Used the `Crypto` prefix for reasons of consistency and better auto-completion without messing up imports on Android and the JVM
 */
typealias CryptoKeyPair = Pair<CryptoPrivateKey, CryptoPublicKey>

val Pair<CryptoPrivateKey, CryptoPublicKey>.public: CryptoPublicKey get() = second
val Pair<CryptoPrivateKey, CryptoPublicKey>.private: CryptoPrivateKey get() = first

/**
 * Little can be gained from abstracting away too many platform specifics, except for unwarranted complexity.
 * Hence, we do not even try to unify the specific properties and characteristics of each platform when it comes to creating and using cryptographic material.
 *
 */
interface PlatformCryptoOpts {
    /*
    /**
     * Use this object to create and use key without authentication
     */
    object NoAuth : PlatformCryptoOpts

    /**
     * A sample pair of biometric auth [PlatformCryptoOpts], which allows for using a key as often as desired within
     * the specified [timeout] after successful biometric authentication.
     */
    class BiometricAuth(val timeout: Duration) {
        /**
         * Use this when creating the key
         */
        val forKeyGeneration: PlatformCryptoOpts = TODO()

        /**
         * Use this when accessing the key to perform cryptographic operations
         */
        val forKeyUsage: PlatformCryptoOpts = TODO()
    }

    */
}

/**
 * The main entry point for managing keys and executing cryptographic operations.
 * On Android it uses the AndroidKeyStore system, on iOS the Keychain.
 *
 * Failure branches of returned  [KmmResult]s are always mapped to a [CryptoException]
 *
 */
object CryptoProvider {

    /**
     * Creates a hardware-backed key pair alongside an attestation proof.
     * For cross-platform consistency reasons, this is always a P256 Key, which may be used for signing and verifying.
     */
    suspend fun createTbaP256Key(
        alias: String,
        attestationChallenge: ByteArray,
        platformSpecifics: PlatformCryptoOpts
    ) = createAttestedP256Key(
        alias,
        attestationChallenge,
        platformSpecifics
    ).mapFailure { if (it !is CryptoException) CryptoExecutionException(it.message, it) else it }

    /**
     * Deletes an Entry (Key, Certificate, …) from the KeyStore/KeyChain. Once it's gone, it's gone!
     *
     * TODO communicate whether key was deleted or not.
     *
     * TODO define behaviour for trying to delete a nonexistent entry
     */
    suspend fun deleteEntry(alias: String, platformSpecifics: PlatformCryptoOpts) =
        clearKey(alias, platformSpecifics).mapFailure {
            if (it !is CryptoException) CryptoExecutionException(
                it.message,
                it
            ) else it
        }

    /**
     * Checks whether a key exists. On iOS, this operation requires authentication, if the key associated with this alias required authentication to be used.
     */
    suspend fun hasKey(alias: String, platformSpecifics: PlatformCryptoOpts) = keyExists(
        alias,
        platformSpecifics
    ).mapFailure { if (it !is CryptoException) CryptoExecutionException(it.message, it) else it }

    /**
     * Creates an EC ([CryptoAlgorithm.ES256], [CryptoAlgorithm.ES384], [CryptoAlgorithm.ES512]) key pair, which can be used to sign and verify data.
     * Only the public key is returned.
     */
    suspend fun createSigningKey(
        alias: String,
        cryptoAlgorithm: CryptoAlgorithm,
        platformSpecifics: PlatformCryptoOpts
    ): KmmResult<CryptoKeyPair> = createKey(
        alias,
        cryptoAlgorithm,
        platformSpecifics
    ).mapFailure { if (it !is CryptoException) CryptoExecutionException(it.message, it) else it }

    /**
     * Signs [data] under the private key associated with [signingKey].
     * @return DER-encoded detached signature
     */
    suspend fun sign(
        data: ByteArray,
        signingKey: CryptoPrivateKey,
        algorithm: CryptoAlgorithm
    ) = signData(
        data,
        signingKey,
        algorithm
    ).mapFailure { if (it !is CryptoException) CryptoExecutionException(it.message, it) else it }

    /**
     * Stores a certificate chain under [alias] in the KeyStore/Keychain.
     * Certificates are always stored s.t. no authentication is required to access them
     * Can obviously be used to store a single certificate too.
     */
    suspend fun storeCertificateChain(
        alias: String,
        certs: CertificateChain,
        platformSpecifics: PlatformCryptoOpts? = null
    ): KmmResult<Unit> = doStoreCertificateChain(
        alias,
        certs,
        platformSpecifics
    ).mapFailure { if (it !is CryptoException) CryptoExecutionException(it.message, it) else it }

    /**
     * Retrieves a previously stored certificate chain. Chains may obviously also contain only a single certificate.
     * Never requires authentication.
     */
    suspend fun getCertificateChain(
        alias: String,
        platformSpecifics: PlatformCryptoOpts? = null
    ): KmmResult<CertificateChain> = doGetCertificateChain(
        alias,
        platformSpecifics
    ).mapFailure { if (it !is CryptoException) CryptoExecutionException(it.message, it) else it }

    /**
     * TODO: Check if necessary
     */
    suspend fun getPublicKey(alias: String, platformSpecifics: PlatformCryptoOpts? = null): KmmResult<CryptoPublicKey> =
        doGetPublicKey(
            alias,
            platformSpecifics
        ).mapFailure { if (it !is CryptoException) CryptoExecutionException(it.message, it) else it }

    /**
     * Verifies [data] against [detachedSignature] under [publicKey] using [algorithm].
     *
     * @param detachedSignature DER-encoded detached signature
     */
    suspend fun verify(
        algorithm: CryptoAlgorithm,
        publicKey: CryptoPublicKey.EC,
        data: ByteArray,
        detachedSignature: CryptoSignature
    ): KmmResult<Boolean> =
        doVerify(
            algorithm,
            publicKey,
            data,
            detachedSignature
        ).mapFailure { if (it !is CryptoException) CryptoExecutionException(it.message, it) else it }

    suspend fun getKeyPair(alias: String, platformSpecifics: PlatformCryptoOpts): KmmResult<CryptoKeyPair> =
        doGetKeyPair(
            alias,
            platformSpecifics
        ).mapFailure { if (it !is CryptoException) CryptoExecutionException(it.message, it) else it }
}

internal expect suspend fun clearKey(alias: String, platformSpecifics: PlatformCryptoOpts): KmmResult<Unit>

internal expect suspend fun keyExists(alias: String, platformSpecifics: PlatformCryptoOpts): KmmResult<Boolean>

internal expect suspend fun createAttestedP256Key(
    alias: String,
    attestationChallenge: ByteArray,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<TbaKey>

internal expect suspend fun createKey(
    alias: String,
    cryptoAlgorithm: CryptoAlgorithm,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<CryptoKeyPair>

internal expect suspend fun signData(
    data: ByteArray,
    signingKey: CryptoPrivateKey,
    algorithm: CryptoAlgorithm
): KmmResult<CryptoSignature>

internal expect suspend fun doVerify(
    algorithm: CryptoAlgorithm,
    publicKey: CryptoPublicKey.EC,
    data: ByteArray,
    detachedSignature: CryptoSignature
): KmmResult<Boolean>


internal expect suspend fun doGetPublicKey(
    alias: String,
    platformSpecifics: PlatformCryptoOpts? = null
): KmmResult<CryptoPublicKey>

internal expect suspend fun doGetKeyPair(alias: String, platformSpecifics: PlatformCryptoOpts): KmmResult<CryptoKeyPair>

internal expect suspend fun doStoreCertificateChain(
    alias: String,
    certs: CertificateChain,
    platformSpecifics: PlatformCryptoOpts?
): KmmResult<Unit>

internal expect suspend fun doGetCertificateChain(
    alias: String,
    platformSpecifics: PlatformCryptoOpts?
): KmmResult<CertificateChain>