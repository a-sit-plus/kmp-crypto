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
import at.asitplus.crypto.provider.CryptoOperationFailed
import at.asitplus.crypto.provider.UnsupportedCryptoException
import at.asitplus.crypto.provider.cfDictionaryOf
import at.asitplus.crypto.provider.corecall
import at.asitplus.crypto.provider.dsl.DSL
import at.asitplus.crypto.provider.dsl.DSLConfigureFn
import at.asitplus.crypto.provider.sign.SignatureInput
import at.asitplus.crypto.provider.sign.Signer
import at.asitplus.crypto.provider.swiftasync
import at.asitplus.crypto.provider.swiftcall
import at.asitplus.crypto.provider.throwCryptoOperationFailed
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
import kotlinx.coroutines.runBlocking
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryCreate
import platform.CoreFoundation.CFRelease
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSBundle
import platform.Foundation.NSData
import platform.Foundation.NSDictionary
import platform.Foundation.create
import platform.Security.SecCopyErrorMessageString
import platform.Security.SecItemCopyMatching
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyGeneratePair
import platform.Security.SecKeyIsAlgorithmSupported
import platform.Security.SecKeyRef
import platform.Security.SecKeyRefVar
import platform.Security.errSecSuccess
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrIsPermanent
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
import secKeyAlgorithm

private object KeychainTags {
    private val tags by lazy {
        val bundleId = NSBundle.mainBundle.bundleIdentifier
            ?: throw UnsupportedCryptoException("Keychain access is unsupported outside of a Bundle")
        Pair("kmp-crypto-privatekey-$bundleId", "kmp-crypto.publickey-$bundleId")
    }
    val PRIVATE_KEYS get() = tags.first
    val PUBLIC_KEYS get() = tags.second
}

class iosSigningKeyConfiguration internal constructor(): PlatformSigningKeyConfiguration<iosSignerConfiguration>() {

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
        val signatureBytes = corecall {
            SecKeyCreateSignature(privateKeyRef, algorithm, CFBridgingRetain(data.data) as? CFDataRef, error)
        }.let { (CFBridgingRelease(it) as NSData).toByteArray() }
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
        override fun bytesToSignature(sigBytes: ByteArray): CryptoSignature {
            TODO("Not yet implemented")
        }
    }

}

sealed class iosSigner<H : unlockedIOSSigner>(
    val alias: String,
    private val config: iosSignerConfiguration
) : Signer.TemporarilyUnlockable<H>() {

    override suspend fun unlock(): KmmResult<H> = catching {
        val arena = Arena()
        val privateKey = arena.alloc<SecKeyRefVar>()
        try {
            memScoped {
                val query = cfDictionaryOf(
                    kSecClass to kSecClassKey,
                    kSecAttrLabel to alias,
                    kSecAttrApplicationTag to KeychainTags.PRIVATE_KEYS,
                    kSecAttrKeyType to when (this@iosSigner) {
                        is ECDSA -> kSecAttrKeyTypeEC
                        is RSA -> kSecAttrKeyTypeRSA
                    },
                    kSecReturnRef to true,
                )
                val status = SecItemCopyMatching(query, privateKey.ptr.reinterpret())
                if ((status == errSecSuccess) && (privateKey.value != null)) {
                    return@memScoped /* continue below try/catch */
                } else {
                    throwCryptoOperationFailed("retrieve private key", status)
                }
            }
        } catch (e: Throwable) {
            arena.clear()
            throw e
        }
        /* if the block did not throw, the handle takes ownership of the arena */
        toUnlocked(arena, privateKey.value!!)
    }

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
    override fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<iosSigningKeyConfiguration>
    ): KmmResult<iosSigner<*>> = catching {
        val config = DSL.resolve(::iosSigningKeyConfiguration, configure)
        val ecConfig = when (val it = config._algSpecific.v) {
            is SigningKeyConfiguration.ECConfiguration -> it
            is SigningKeyConfiguration.RSAConfiguration -> throw UnsupportedCryptoException("The iOS secure enclave only supports ECDSA keys on P-256")
        }
        if (ecConfig.curve != ECCurve.SECP_256_R_1) {
            throw UnsupportedCryptoException("The iOS secure enclave only supports ECDSA keys on P-256")
        }

        val publicKeyBytes: ByteArray = memScoped {
            val attr = cfDictionaryOf(
                kSecAttrKeyType to kSecAttrKeyTypeEC,
                kSecAttrKeySizeInBits to 256,
                kSecAttrTokenID to kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs to cfDictionaryOf(
                    kSecAttrLabel to alias,
                    kSecAttrIsPermanent to true,
                    kSecAttrApplicationTag to KeychainTags.PRIVATE_KEYS
                ),
                kSecPublicKeyAttrs to cfDictionaryOf(
                    kSecAttrLabel to alias,
                    kSecAttrIsPermanent to false,
                    kSecAttrApplicationTag to KeychainTags.PUBLIC_KEYS
                )
            )
            val pubkey = alloc<SecKeyRefVar>()
            val privkey = alloc<SecKeyRefVar>()
            val status = SecKeyGeneratePair(attr, pubkey.ptr, privkey.ptr)
            if ((status == errSecSuccess) && (pubkey.value != null) && (privkey.value != null)) {
                return@memScoped corecall {
                    SecKeyCopyExternalRepresentation(pubkey.value, error)
                }.let { CFBridgingRelease(it) as NSData }.toByteArray()
            } else {
                throwCryptoOperationFailed("generate key", status)
            }
        }
        iosSigner.ECDSA(alias,
            DSL.resolve(::iosSignerConfiguration, config.signer.v),
            CryptoPublicKey.EC.fromAnsiX963Bytes(ECCurve.SECP_256_R_1, publicKeyBytes))

    }

    override fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<iosSignerConfiguration>
    ): KmmResult<iosSigner<*>> = catching {
        val config = DSL.resolve(::iosSignerConfiguration, configure)
        val publicKeyBytes: ByteArray = memScoped {
            val publicKey = alloc<SecKeyRefVar>()
            val query = cfDictionaryOf(
                kSecClass to kSecClassKey,
                kSecAttrLabel to alias,
                kSecAttrApplicationTag to KeychainTags.PUBLIC_KEYS,
                kSecReturnRef to true,
            )
            val status = SecItemCopyMatching(query, publicKey.ptr.reinterpret())
            if ((status == errSecSuccess) && (publicKey.value != null)) {
                return@memScoped corecall {
                    SecKeyCopyExternalRepresentation(publicKey.value, error)
                }.let { CFBridgingRelease(it) as NSData }.toByteArray()
            } else {
                throwCryptoOperationFailed("retrieve public key", status)
            }
        }
        return@catching when (val publicKey = CryptoPublicKey.fromIosEncoded(publicKeyBytes)) {
            is CryptoPublicKey.EC -> iosSigner.ECDSA(alias, config, publicKey)
            is CryptoPublicKey.Rsa -> iosSigner.RSA(alias, config, publicKey)
        }
    }

    override fun deleteSigningKey(alias: String) {
        TODO("Not yet implemented")
    }

}
