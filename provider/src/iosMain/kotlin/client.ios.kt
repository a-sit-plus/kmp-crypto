package at.asitplus.crypto.provider

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.failure
import at.asitplus.KmmResult.Companion.success
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.pki.CertificateChain
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.swift.krypto.Krypto
import kotlinx.cinterop.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import platform.Foundation.CFBridgingRelease
import platform.Foundation.NSData
import platform.Foundation.create
import platform.posix.memcpy

class IosPrivateKey(val alias: String, platformSpecifics: IosSpecificCryptoOps) :
    CryptoPrivateKey(Platform.iOS, platformSpecifics)


@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun createAttestedP256Key(
    alias: String,
    attestationChallenge: ByteArray,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<TbaKey> {
    if (platformSpecifics !is IosSpecificCryptoOps) return KmmResult.failure(
        InvalidParameterException(
            platformSpecifics,
            "iOS requires IosSpecificCryptoOps"
        )
    )
    val mut = Mutex(true)
    var key: KmmResult<TbaKey>? = null
    Krypto.createAttestedKey(
        alias,
        attestationChallenge.toNSData(),
        (platformSpecifics.keyProperties.toMutableList()).associate { (k, v) ->
            CFBridgingRelease(k) to CFBridgingRelease(v)
        },
        platformSpecifics.accessibilityValue,
        platformSpecifics.secAccessControlFlags,
        platformSpecifics.authCtx as objcnames.classes.LAContext?
    ) { att, err ->
        att?.let {
            key = runCatching {
                TbaKey(IosPrivateKey(
                    alias,
                    platformSpecifics.authContainer?.opsForUse ?: platformSpecifics
                ).also { it.authContainer = platformSpecifics.authContainer } to CryptoPublicKey.decodeFromDer(
                    it.publicKey().toByteArray()
                ) as CryptoPublicKey.EC,
                    it.attestationStatement().map { (it as NSData).toByteArray() })
            }.wrap()
            mut.unlock()
        }
        err?.let {
            key = KmmResult.failure(CryptoExecutionException(it.localizedDescription))
            mut.unlock()
        }

    }


    mut.withLock {
        return key!!
    }
}

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun createKey(
    alias: String,
    cryptoAlgorithm: CryptoAlgorithm,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<CryptoKeyPair> {
    if (platformSpecifics !is IosSpecificCryptoOps) return KmmResult.failure(
        InvalidParameterException(
            platformSpecifics,
            "iOS requires IosSpecificCryptoOps"
        )
    )

    val mut = Mutex(true)
    var key: KmmResult<CryptoKeyPair>? = null
    Krypto.createSigningKey(
        alias,
        when (cryptoAlgorithm) {
            CryptoAlgorithm.ES256, CryptoAlgorithm.ES384, CryptoAlgorithm.ES512 -> cryptoAlgorithm.name
            else -> return KmmResult.failure(
                UnsupportedAlgorithmException(
                    cryptoAlgorithm,
                    "UnsupportedAlgorithm: $cryptoAlgorithm"
                )
            )
        },
        platformSpecifics.keyProperties.toMutableList().associate { (k, v) ->
            CFBridgingRelease(k) to CFBridgingRelease(v)
        },
        platformSpecifics.accessibilityValue,
        platformSpecifics.secAccessControlFlags,
        platformSpecifics.authCtx as objcnames.classes.LAContext?
    ) { derEncoded, err ->
        derEncoded?.let {
            key =
                runCatching {
                    IosPrivateKey(
                        alias,
                        platformSpecifics.authContainer?.opsForUse ?: platformSpecifics
                    ).also {
                        it.authContainer = platformSpecifics.authContainer
                    } to (CryptoPublicKey.decodeFromDer(it.toByteArray()) as CryptoPublicKey.EC)
                }.wrap()
            mut.unlock()
        }
        err?.let {
            key = KmmResult.failure(CryptoExecutionException(it.localizedDescription))
            mut.unlock()
        }

    }
    mut.withLock {
        return key!!
    }
}

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun keyExists(alias: String, platformSpecifics: PlatformCryptoOpts): KmmResult<Boolean> =
    if (platformSpecifics !is IosSpecificCryptoOps) KmmResult.failure(
        InvalidParameterException(
            platformSpecifics,
            "iOS requires IosSpecificCryptoOps"
        )
    )
    else runCatching { Krypto.keyExists(alias, platformSpecifics.authCtx as objcnames.classes.LAContext?) }.wrap()


@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun clearKey(alias: String, platformSpecifics: PlatformCryptoOpts): KmmResult<Unit> =
    if (platformSpecifics !is IosSpecificCryptoOps) KmmResult.failure(
        InvalidParameterException(
            platformSpecifics,
            "iOS requires IosSpecificCryptoOps"
        )
    )
    else runCatching { Krypto.clear(alias, platformSpecifics.authCtx as objcnames.classes.LAContext?) }.wrap()

@OptIn(ExperimentalForeignApi::class)
actual suspend fun signData(
    data: ByteArray,
    signingKey: CryptoPrivateKey,
    algorithm: CryptoAlgorithm
): KmmResult<CryptoSignature> {
    if (signingKey !is IosPrivateKey) return KmmResult.failure(
        InvalidParameterException(
            signingKey.platformSpecifics,
            "iOS requires IosPrivateKey"
        )
    )
    signingKey.reAuth()
    val platformSpecifics = signingKey.platformSpecifics
    if (platformSpecifics !is IosSpecificCryptoOps) return KmmResult.failure(
        InvalidParameterException(
            platformSpecifics,
            "iOS requires IosSpecificCryptoOps"
        )
    )
    var res: KmmResult<ByteArray>? = null
    val mut = Mutex(locked = true)
    Krypto.sign(
        data.toNSData(),
        signingKey.alias,
        algorithm.name,
        platformSpecifics.keyProperties.toMutableList().associate { (k, v) ->
            CFBridgingRelease(k) to CFBridgingRelease(v)
        },
        platformSpecifics.authCtx as objcnames.classes.LAContext?
    ) { signature, err ->
        signature?.let {
            res = KmmResult.success(signature.toByteArray())
            mut.unlock()
        }

        err?.let {
            res = KmmResult.failure(CryptoExecutionException(it.localizedDescription))
            mut.unlock()
        }
    }
    mut.withLock {
        return res!!.mapCatching { CryptoSignature.decodeFromDer(it) }.mapFailure { EncodingException(it.message, it) }
    }
}

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun doVerify(
    algorithm: CryptoAlgorithm,
    publicKey: CryptoPublicKey.EC,
    data: ByteArray,
    detachedSignature: CryptoSignature
): KmmResult<Boolean> {
    var res: KmmResult<Boolean>? = null
    val mut = Mutex(locked = true)
    Krypto.verify(
        algorithm.name,
        publicKey.encodeToDer().toNSData(),
        detachedSignature.encodeToDer().toNSData(),
        data.toNSData()
    ) { bool, err ->
        bool?.let {
            res = KmmResult.success(it.toBoolean())
            mut.unlock()
        }
        err?.let {
            res = failure(CryptoExecutionException(it.localizedDescription))
            mut.unlock()
        }
    }
    mut.withLock { return res!! }
}


@OptIn(ExperimentalForeignApi::class)
fun NSData.toByteArray(): ByteArray = ByteArray(length.toInt()).apply {
    usePinned {
        memcpy(it.addressOf(0), bytes, length)
    }
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
fun ByteArray.toNSData(): NSData = memScoped {
    NSData.create(bytes = allocArrayOf(this@toNSData), length = this@toNSData.size.toULong())
}

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun doGetPublicKey(
    alias: String,
    platformSpecifics: PlatformCryptoOpts?
): KmmResult<CryptoPublicKey> {
    if (platformSpecifics != null && platformSpecifics !is IosSpecificCryptoOps) return KmmResult.failure(
        InvalidParameterException(platformSpecifics, "IosSpecifics required")
    )
    var res: KmmResult<CryptoPublicKey>? = null
    val mut = Mutex(locked = true)
    Krypto.getPublicKey(alias) { derEncoded, err ->
        derEncoded?.let {
            res = runCatching { CryptoPublicKey.decodeFromDer(it.toByteArray()) }.wrap()
            mut.unlock()
        }
        err?.let {
            res = failure(CryptoExecutionException(it.localizedDescription))
            mut.unlock()
        }
    }
    mut.withLock { return res!! }
}


internal actual suspend fun doGetKeyPair(
    alias: String,
    platformSpecifics: PlatformCryptoOpts
): KmmResult<CryptoKeyPair> =
    keyExists(alias, platformSpecifics).mapCatching {
        if (it) {
            IosPrivateKey(alias, platformSpecifics as IosSpecificCryptoOps) to doGetPublicKey(
                alias,
                platformSpecifics
            ).getOrThrow() as CryptoPublicKey.EC
        } else throw CryptoObjectNotFoundException("Key not found")
    }


@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun doGetCertificateChain(
    alias: String,
    platformSpecifics: PlatformCryptoOpts?
): KmmResult<CertificateChain> {
    var res: KmmResult<CertificateChain>? = null
    val mut = Mutex(locked = true)
    Krypto.getCertificate(alias) { asn1Sequence, err ->
        asn1Sequence?.let {
            res = runCatching {
                (Asn1Element.parse(it.toByteArray()) as Asn1Sequence).children.map {
                    X509Certificate.decodeFromTlv(it as Asn1Sequence)
                }
            }.wrap().mapFailure {
                if (it is Asn1Exception) EncodingException(it.message, it)
                else it //TODO
            }
            mut.unlock()
        }
        err?.let {
            res = failure(CryptoExecutionException(it.localizedDescription))
            mut.unlock()
        }
    }
    mut.withLock { return res!! }
}

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun doStoreCertificateChain(
    alias: String,
    certs: CertificateChain,
    platformSpecifics: PlatformCryptoOpts?
): KmmResult<Unit> {
    var res: KmmResult<Unit>? = null
    val mut = Mutex(locked = true)
    Krypto.storeCertificateChain(alias, runCatching {
        Asn1.Sequence {
            certs.forEach { +it }
        }.derEncoded.toNSData()
    }.wrap().mapFailure { EncodingException(it.message, it) }.getOrThrow()) { ok, err ->
        ok?.let {
            res = success(Unit)
            mut.unlock()
        }
        err?.let {
            res = failure(CryptoExecutionException(it.localizedDescription))
            mut.unlock()
        }
    }
    mut.withLock { return res!! }
}
