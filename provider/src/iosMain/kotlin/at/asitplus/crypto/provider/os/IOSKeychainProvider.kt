@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.crypto.provider.os

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.RSAPadding
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.datatypes.nativeDigest
import at.asitplus.crypto.provider.CFCryptoOperationFailed
import at.asitplus.crypto.provider.CryptoOperationFailed
import at.asitplus.crypto.provider.UnsupportedCryptoException
import at.asitplus.crypto.provider.createCFDictionary
import at.asitplus.crypto.provider.cfDictionaryOf
import at.asitplus.crypto.provider.corecall
import at.asitplus.crypto.provider.dsl.DSL
import at.asitplus.crypto.provider.dsl.DSLConfigureFn
import at.asitplus.crypto.provider.giveToCF
import at.asitplus.crypto.provider.sign.SignatureInput
import at.asitplus.crypto.provider.sign.Signer
import at.asitplus.crypto.provider.takeFromCF
import at.asitplus.crypto.provider.toByteArray
import at.asitplus.crypto.provider.toNSData
import kotlinx.cinterop.Arena
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.value
import kotlinx.coroutines.newFixedThreadPoolContext
import kotlinx.coroutines.withContext
import platform.CoreFoundation.kCFAllocatorDefault
import platform.Foundation.CFBridgingRelease
import platform.Foundation.NSBundle
import platform.Foundation.NSData
import platform.Security.SecAccessControlCreateWithFlags
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyGeneratePair
import platform.Security.SecKeyIsAlgorithmSupported
import platform.Security.SecKeyRef
import platform.Security.SecKeyRefVar
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAccessControlBiometryAny
import platform.Security.kSecAccessControlDevicePasscode
import platform.Security.kSecAccessControlPrivateKeyUsage
import platform.Security.kSecAccessControlUserPresence
import platform.Security.kSecAttrAccessControl
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlock
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import platform.Security.kSecAttrAccessibleAlways
import platform.Security.kSecAttrAccessibleAlwaysThisDeviceOnly
import platform.Security.kSecAttrAccessibleWhenUnlocked
import platform.Security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrIsPermanent
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPrivate
import platform.Security.kSecAttrKeyClassPublic
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeEC
import platform.Security.kSecAttrKeyTypeRSA
import platform.Security.kSecAttrLabel
import platform.Security.kSecAttrTokenID
import platform.Security.kSecAttrTokenIDSecureEnclave
import platform.Security.kSecClass
import platform.Security.kSecClassKey
import platform.Security.kSecKeyOperationTypeSign
import platform.Security.kSecPrivateKeyAttrs
import platform.Security.kSecPublicKeyAttrs
import platform.Security.kSecReturnRef
import platform.Security.kSecUseAuthenticationUI
import platform.Security.kSecUseAuthenticationUIAllow
import platform.Security.kSecUseOperationPrompt
import secKeyAlgorithm

val keychainThreads = newFixedThreadPoolContext(nThreads = 4, name = "iOS Keychain Operations")

private object KeychainTags {
    private val tags by lazy {
        val bundleId = NSBundle.mainBundle.bundleIdentifier
            ?: throw UnsupportedCryptoException("Keychain access is unsupported outside of a Bundle")
        Pair("kmp-crypto-privatekey-$bundleId", "kmp-crypto.publickey-$bundleId")
    }
    val PRIVATE_KEYS get() = tags.first
    val PUBLIC_KEYS get() = tags.second
}

class iosTPMConfiguration internal constructor() : PlatformSigningKeyConfiguration.TPMConfiguration() {
    /** Set to true (default) to require secure enclave protection. Set to false to trust keychain protection. */
    var requireSecureEnclave = true
    /** Set to true to allow this key to be backed up. */
    var allowBackup = false
    enum class Availability { ALWAYS, AFTER_FIRST_UNLOCK, WHILE_UNLOCKED }
    /** Specify when this key should be available */
    var availability = Availability.ALWAYS
}
class iosSigningKeyConfiguration internal constructor(): PlatformSigningKeyConfiguration<iosSignerConfiguration>() {
    override val tpm = childOrDefault(::iosTPMConfiguration) {
        requireSecureEnclave = false
    }
}

class iosSignerConfiguration internal constructor(): SignerConfiguration() {
}

sealed class unlockedIOSSigner(private val ownedArena: Arena, private val privateKeyRef: SecKeyRef) : Signer.UnlockedHandle {
    abstract val parent: iosSigner<*>
    val alias get() = parent.alias

    var usable = true
    final override fun close() {
        if (!usable) return
        usable = false
        ownedArena.clear()
    }

    internal fun checkSupport() {
        if (!SecKeyIsAlgorithmSupported(privateKeyRef, kSecKeyOperationTypeSign, signatureAlgorithm.secKeyAlgorithm)) {
            close()
            throw UnsupportedCryptoException("Requested operation is not supported by this key")
        }
    }

    protected abstract fun bytesToSignature(sigBytes: ByteArray): CryptoSignature
    override fun sign(data: SignatureInput): KmmResult<CryptoSignature> = catching {
        if (!usable) throw IllegalStateException("Scoping violation; using key after it has been freed")
        require(data.format == null) { "Pre-hashed data is unsupported on iOS" }
        val algorithm = signatureAlgorithm.secKeyAlgorithm
        val plaintext = data.data.fold(byteArrayOf(), ByteArray::plus).toNSData()
        val signatureBytes = corecall {
            SecKeyCreateSignature(privateKeyRef, algorithm, plaintext.giveToCF(), error)
        }.let { it.takeFromCF<NSData>().toByteArray() }
        return@catching bytesToSignature(signatureBytes)
    }

    class ECDSA(ownedArena: Arena,
                privateKeyRef: SecKeyRef,
                override val parent: iosSigner.ECDSA)
                : unlockedIOSSigner(ownedArena, privateKeyRef), Signer.ECDSA
    {
        override val signatureAlgorithm get() = parent.signatureAlgorithm
        override val publicKey get() = parent.publicKey
        override fun bytesToSignature(sigBytes: ByteArray) =
            CryptoSignature.EC.decodeFromDer(sigBytes).withCurve(publicKey.curve)
    }

    class RSA(ownedArena: Arena,
              privateKeyRef: SecKeyRef,
              override val parent: iosSigner.RSA)
              : unlockedIOSSigner(ownedArena, privateKeyRef), Signer.RSA
    {
        override val signatureAlgorithm get() = parent.signatureAlgorithm
        override val publicKey get() = parent.publicKey
        override fun bytesToSignature(sigBytes: ByteArray) =
            CryptoSignature.RSAorHMAC(sigBytes)
    }

}

sealed class iosSigner<H : unlockedIOSSigner>(
    val alias: String,
    private val config: iosSignerConfiguration
) : Signer.TemporarilyUnlockable<H>() {

    override suspend fun unlock(): KmmResult<H> = withContext(keychainThreads) { catching {
        val arena = Arena()
        val privateKey = arena.alloc<SecKeyRefVar>()
        try {
            memScoped {
                val query = cfDictionaryOf(
                    kSecClass to kSecClassKey,
                    kSecAttrKeyClass to kSecAttrKeyClassPrivate,
                    kSecAttrLabel to alias,
                    kSecAttrApplicationTag to KeychainTags.PRIVATE_KEYS,
                    kSecAttrKeyType to when (this@iosSigner) {
                        is ECDSA -> kSecAttrKeyTypeEC
                        is RSA -> kSecAttrKeyTypeRSA
                    },
                    kSecReturnRef to true,

                    kSecUseOperationPrompt to config.unlockPrompt.v.message,
                    kSecUseAuthenticationUI to kSecUseAuthenticationUIAllow
                )
                val status = SecItemCopyMatching(query, privateKey.ptr.reinterpret())
                if ((status == errSecSuccess) && (privateKey.value != null)) {
                    return@memScoped /* continue below try/catch */
                } else {
                    throw CFCryptoOperationFailed(thing = "retrieve private key", osStatus = status)
                }
            }
        } catch (e: Throwable) {
            arena.clear()
            throw e
        }
        /* if the block did not throw, the handle takes ownership of the arena */
        toUnlocked(arena, privateKey.value!!).also(unlockedIOSSigner::checkSupport)
    }}

    protected abstract fun toUnlocked(arena: Arena, key: SecKeyRef): H
    class ECDSA(alias: String, config: iosSignerConfiguration,
                override val publicKey: CryptoPublicKey.EC)
                : iosSigner<unlockedIOSSigner.ECDSA>(alias, config), Signer.ECDSA
    {
        override val signatureAlgorithm = when (val digest = if (config.ec.v.digestSpecified) config.ec.v.digest else publicKey.curve.nativeDigest){
            Digest.SHA256, Digest.SHA384, Digest.SHA512 -> SignatureAlgorithm.ECDSA(digest, publicKey.curve)
            else -> throw UnsupportedCryptoException("ECDSA with $digest is not supported on iOS")
        }

        override fun toUnlocked(arena: Arena, key: SecKeyRef) =
            unlockedIOSSigner.ECDSA(arena, key, this)
    }

    class RSA(alias: String, config: iosSignerConfiguration,
                override val publicKey: CryptoPublicKey.Rsa)
                : iosSigner<unlockedIOSSigner.RSA>(alias, config), Signer.RSA
    {
        override val signatureAlgorithm = SignatureAlgorithm.RSA(
            digest = if (config.rsa.v.digestSpecified) config.rsa.v.digest else Digest.SHA512,
            padding = if (config.rsa.v.paddingSpecified) config.rsa.v.padding else RSAPadding.PSS)

        override fun toUnlocked(arena: Arena, key: SecKeyRef) =
            unlockedIOSSigner.RSA(arena, key, this)
    }
}

@OptIn(ExperimentalForeignApi::class)
object IOSKeychainProvider:  TPMSigningProviderI<iosSigner<*>, iosSignerConfiguration, iosSigningKeyConfiguration> {
    private fun MemScope.getPublicKey(alias: String): SecKeyRef? {
        val it = alloc<SecKeyRefVar>()
        val query = cfDictionaryOf(
            kSecClass to kSecClassKey,
            kSecAttrKeyClass to kSecAttrKeyClassPublic,
            kSecAttrLabel to alias,
            kSecAttrApplicationTag to KeychainTags.PUBLIC_KEYS,
            kSecReturnRef to true,
        )
        val status = SecItemCopyMatching(query, it.ptr.reinterpret())
        return when (status) {
            errSecSuccess -> it.value
            errSecItemNotFound -> null
            else -> {
                throw CFCryptoOperationFailed(thing = "retrieve public key", osStatus = status)
            }
        }
    }
    override fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<iosSigningKeyConfiguration>
    ): KmmResult<iosSigner<*>> = catching {
        memScoped {
            if (getPublicKey(alias) != null)
                throw NoSuchElementException("Key with alias $alias already exists")
        }
        deleteSigningKey(alias) /* make sure there are no leftover private keys */

        val config = DSL.resolve(::iosSigningKeyConfiguration, configure)

        val publicKeyBytes: ByteArray = memScoped {
            val availability = config.tpm.v.let { c-> when (c.availability) {
                iosTPMConfiguration.Availability.ALWAYS -> if (c.allowBackup) kSecAttrAccessibleAlways else kSecAttrAccessibleAlwaysThisDeviceOnly
                iosTPMConfiguration.Availability.AFTER_FIRST_UNLOCK -> if (c.allowBackup) kSecAttrAccessibleAfterFirstUnlock else kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                iosTPMConfiguration.Availability.WHILE_UNLOCKED -> if (c.allowBackup) kSecAttrAccessibleWhenUnlocked else kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            } }
            val attr = createCFDictionary {
                when (val alg = config._algSpecific.v) {
                    is SigningKeyConfiguration.ECConfiguration -> {
                        kSecAttrKeyType mapsTo kSecAttrKeyTypeEC
                        kSecAttrKeySizeInBits mapsTo alg.curve.coordinateLength.bits.toInt()
                    }
                    is SigningKeyConfiguration.RSAConfiguration -> {
                        kSecAttrKeyType mapsTo kSecAttrKeyTypeRSA
                        kSecAttrKeySizeInBits mapsTo alg.bits
                    }
                }
                if (config.tpm.v.requireSecureEnclave) {
                    kSecAttrTokenID mapsTo kSecAttrTokenIDSecureEnclave
                }
                kSecPrivateKeyAttrs mapsTo createCFDictionary {
                    kSecAttrLabel mapsTo alias
                    kSecAttrIsPermanent mapsTo true
                    kSecAttrApplicationTag mapsTo KeychainTags.PRIVATE_KEYS
                    when (val factors = config.tpm.v.protection.v?.factors?.v) {
                        null -> {
                            kSecAttrAccessible mapsTo availability
                        }
                        else -> {
                            kSecAttrAccessControl mapsTo corecall {
                                SecAccessControlCreateWithFlags(
                                    null, availability,
                                    when {
                                        (factors.biometry && factors.deviceLock) -> kSecAccessControlUserPresence
                                        factors.biometry -> kSecAccessControlBiometryAny
                                        else -> kSecAccessControlDevicePasscode
                                    }, error)
                            }.also { defer { CFBridgingRelease(it) } }
                        }
                    }

                }
                kSecPublicKeyAttrs mapsTo cfDictionaryOf(
                    kSecAttrLabel to alias,
                    kSecAttrIsPermanent to true,
                    kSecAttrApplicationTag to KeychainTags.PUBLIC_KEYS
                )
            }

            val pubkey = alloc<SecKeyRefVar>()
            val privkey = alloc<SecKeyRefVar>()

            val status = SecKeyGeneratePair(attr, pubkey.ptr, privkey.ptr)

            if ((status == errSecSuccess) && (pubkey.value != null) && (privkey.value != null)) {
                return@memScoped corecall {
                    SecKeyCopyExternalRepresentation(pubkey.value, error)
                }.let { it.takeFromCF<NSData>() }.toByteArray()
            } else {
                throw CFCryptoOperationFailed(thing = "generate key", osStatus = status)
            }
        }

        val signerConfiguration = DSL.resolve(::iosSignerConfiguration, config.signer.v)
        return@catching when (val alg = config._algSpecific.v) {
            is SigningKeyConfiguration.ECConfiguration ->
                iosSigner.ECDSA(alias, signerConfiguration,
                    CryptoPublicKey.EC.fromAnsiX963Bytes(alg.curve, publicKeyBytes))
            is SigningKeyConfiguration.RSAConfiguration ->
                iosSigner.RSA(alias, signerConfiguration,
                    CryptoPublicKey.Rsa.fromPKCS1encoded(publicKeyBytes))
        }
    }

    override fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<iosSignerConfiguration>
    ): KmmResult<iosSigner<*>> = catching {
        val config = DSL.resolve(::iosSignerConfiguration, configure)
        val publicKeyBytes: ByteArray = memScoped {
            val publicKey = getPublicKey(alias)
                ?: throw NoSuchElementException("No key for alias $alias exists")
            return@memScoped corecall {
                SecKeyCopyExternalRepresentation(publicKey, error)
            }.let { it.takeFromCF<NSData>() }.toByteArray()
        }
        return@catching when (val publicKey = CryptoPublicKey.fromIosEncoded(publicKeyBytes)) {
            is CryptoPublicKey.EC -> iosSigner.ECDSA(alias, config, publicKey)
            is CryptoPublicKey.Rsa -> iosSigner.RSA(alias, config, publicKey)
        }
    }

    override fun deleteSigningKey(alias: String) {
        memScoped {
            mapOf(
                "public" to cfDictionaryOf(
                    kSecClass to kSecClassKey,
                    kSecAttrKeyClass to kSecAttrKeyClassPublic,
                    kSecAttrLabel to alias,
                    kSecAttrApplicationTag to KeychainTags.PUBLIC_KEYS
                ), "private" to cfDictionaryOf(
                    kSecClass to kSecClassKey,
                    kSecAttrKeyClass to kSecAttrKeyClassPrivate,
                    kSecAttrLabel to alias,
                    kSecAttrApplicationTag to KeychainTags.PRIVATE_KEYS
                )
            ).map { (kind, options) ->
                val status = SecItemDelete(options)
                if ((status != errSecSuccess) && (status != errSecItemNotFound))
                    CFCryptoOperationFailed(thing = "delete $kind key", osStatus = status)
                else
                    null
            }.mapNotNull { it?.message }.let {
                if (it.isNotEmpty())
                    throw CryptoOperationFailed(it.joinToString(","))
            }
        }
    }

}
