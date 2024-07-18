@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.crypto.provider.os

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.provider.UnsupportedCryptoException
import at.asitplus.crypto.provider.dsl.DSL
import at.asitplus.crypto.provider.dsl.DSLConfigureFn
import at.asitplus.crypto.provider.sign.SignatureInput
import at.asitplus.crypto.provider.sign.Signer
import at.asitplus.crypto.provider.swiftasync
import at.asitplus.crypto.provider.swiftcall
import at.asitplus.crypto.provider.toByteArray
import at.asitplus.crypto.provider.toNSData
import at.asitplus.swift.krypto.Krypto
import at.asitplus.swift.krypto.SignerProxy
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.runBlocking
import platform.Foundation.NSBundle
import platform.Foundation.NSData

class iosSigningKeyConfiguration internal constructor(): PlatformSigningKeyConfiguration<iosSignerConfiguration>() {

}

class iosSignerConfiguration internal constructor(): SignerConfiguration() {

}

class iosEnclaveSigner (private val proxy: SignerProxy, override val signatureAlgorithm: SignatureAlgorithm.ECDSA): Signer.Unlocked, Signer.ECDSA {
    override val publicKey = swiftcall { proxy.getPublicKeyAndReturnError(error) }.let(NSData::toByteArray).let {
        CryptoPublicKey.EC.fromAnsiX963Bytes(ECCurve.SECP_256_R_1, it)
    }

    override fun sign(data: SignatureInput): KmmResult<CryptoSignature> = catching {
        require(data.format == null) { "Pre-hashed data is unsupported on iOS" }
        val sigBytes = swiftcall {
            proxy.signAndReturnError(
                signatureAlgorithm.digest.toString(),
                data.data.fold(byteArrayOf(), ByteArray::plus).toNSData(),
                error)
        }
        CryptoSignature.EC.decodeFromDer(sigBytes).withCurve(ECCurve.SECP_256_R_1)
    }
}
@OptIn(ExperimentalForeignApi::class)
object IOSKeychainProvider:  TPMSigningProviderI<iosEnclaveSigner, iosSignerConfiguration, iosSigningKeyConfiguration> {

    private fun getSignerFromProxy(proxy: SignerProxy, config: iosSignerConfiguration): iosEnclaveSigner {
        val ecConfig = config.ec.v
        val digest = if (ecConfig.digestSpecified) ecConfig.digest else Digest.SHA256
        when (digest) {
            Digest.SHA256, Digest.SHA384, Digest.SHA512 -> {}
            else -> throw UnsupportedCryptoException("Requested digest $digest is unsupported on iOS")
        }
    }
    override fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<iosSigningKeyConfiguration>
    ): KmmResult<iosEnclaveSigner> = catching {
        val config = DSL.resolve(::iosSigningKeyConfiguration, configure)
        val ecConfig = when (val it = config._algSpecific.v) {
            is SigningKeyConfiguration.ECConfiguration -> it
            is SigningKeyConfiguration.RSAConfiguration -> throw UnsupportedCryptoException("The iOS secure enclave only supports ECDSA keys on P-256")
        }
        if (ecConfig.curve != ECCurve.SECP_256_R_1) {
            throw UnsupportedCryptoException("The iOS secure enclave only supports ECDSA keys on P-256")
        }
        swiftcall {
            Krypto.createAttestedP256Key(alias, error)
        }.let {
            getSignerFromProxy(it, DSL.resolve(::iosSignerConfiguration, config.signer.v))
        }
    }

    override fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<iosSignerConfiguration>
    ): KmmResult<iosEnclaveSigner> {
        TODO("Not yet implemented")
    }

    override fun deleteSigningKey(alias: String) {
        TODO("Not yet implemented")
    }

}
