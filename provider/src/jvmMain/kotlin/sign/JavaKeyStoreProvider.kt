package at.asitplus.crypto.provider.sign

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.X509SignatureAlgorithm
import at.asitplus.crypto.datatypes.asn1.Asn1String
import at.asitplus.crypto.datatypes.asn1.Asn1Time
import at.asitplus.crypto.datatypes.fromJcaPublicKey
import at.asitplus.crypto.datatypes.jcaName
import at.asitplus.crypto.datatypes.parseFromJca
import at.asitplus.crypto.datatypes.pki.AttributeTypeAndValue
import at.asitplus.crypto.datatypes.pki.CertificateChain
import at.asitplus.crypto.datatypes.pki.RelativeDistinguishedName
import at.asitplus.crypto.datatypes.pki.TbsCertificate
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.datatypes.pki.leaf
import at.asitplus.crypto.provider.DSL
import at.asitplus.crypto.provider.OSSigningKeyStoreI
import at.asitplus.crypto.provider.SignerConfiguration
import at.asitplus.crypto.provider.SigningKeyConfiguration
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import kotlinx.datetime.Clock
import org.kotlincrypto.SecureRandom
import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import at.asitplus.crypto.provider.sign.Signer as SignerI
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

class JavaSigningKeyConfiguration: SigningKeyConfiguration() {
    var provider: String = "BC"
    var privateKeyPassword: CharArray? = null
    var certificateValidityPeriod: Duration = 1.days
}
class JavaSignerConfiguration: SignerConfiguration() {
    var provider: String = "BC"
    var privateKeyPassword: CharArray? = null
}

class JavaKeyStoreProvider constructor (private val ks: KeyStore)
    : OSSigningKeyStoreI<JavaSigningKeyConfiguration, JavaSignerConfiguration> {

    constructor(provider: String = "BC") :
            this(KeyStore.getInstance(KeyStore.getDefaultType(), provider).apply { load(null) })
    override fun createSigningKey(
        alias: String,
        configure: (JavaSigningKeyConfiguration.() -> Unit)?
    ): CryptoPublicKey {
        if (ks.containsAlias(alias))
            throw IllegalStateException("Key with alias already exists")

        val config = DSL.resolve(::JavaSigningKeyConfiguration, configure)

        val spec = when (val algSpec = config._algSpecific.v) {
            is SigningKeyConfiguration.RSAConfiguration ->
                RSAKeyGenParameterSpec(algSpec.bits, algSpec.publicExponent.toJavaBigInteger())
            is SigningKeyConfiguration.ECConfiguration ->
                ECGenParameterSpec(algSpec.curve.jcaName)
        }
        val keyPair = KeyPairGenerator.getInstance(when (config._algSpecific.v) {
            is SigningKeyConfiguration.RSAConfiguration -> "RSA"
            is SigningKeyConfiguration.ECConfiguration -> "EC"
        }, config.provider).run {
            initialize(spec)
            genKeyPair()
        }
        val sigAlg = when (config._algSpecific.v) {
            is SigningKeyConfiguration.RSAConfiguration -> X509SignatureAlgorithm.RS256
            is SigningKeyConfiguration.ECConfiguration -> X509SignatureAlgorithm.ES256
        }
        val publicKey = CryptoPublicKey.fromJcaPublicKey(keyPair.public).getOrThrow()
        val tbsCert = TbsCertificate(
            serialNumber = SecureRandom().nextBytesOf(32),
            signatureAlgorithm = sigAlg,
            issuerName = listOf(
                RelativeDistinguishedName(
                    AttributeTypeAndValue.CommonName(
                        Asn1String.UTF8(alias)))
            ),
            subjectName = listOf(
                RelativeDistinguishedName(
                    AttributeTypeAndValue.CommonName(
                        Asn1String.UTF8(alias)))
            ),
            validFrom = Asn1Time(Clock.System.now()),
            validUntil = Asn1Time(Clock.System.now() + config.certificateValidityPeriod),
            publicKey = publicKey
        )
        val certSig = Signature.getInstance(sigAlg.jcaName, config.provider).run {
            initSign(keyPair.private)
            update(tbsCert.encodeToDer())
            sign()
        }.let { CryptoSignature.parseFromJca(it, sigAlg) }
        val cert = X509Certificate(tbsCert, sigAlg, certSig)
        ks.setKeyEntry(alias, keyPair.private, config.privateKeyPassword,
            arrayOf(CertificateFactory.getInstance("X.509", config.provider).run {
                generateCertificate(ByteArrayInputStream(cert.encodeToDer()))
            }))
        return publicKey
    }

    override fun hasSigningKey(alias: String) = ks.containsAlias(alias)

    override fun deleteSigningKey(alias: String) {
        if (ks.containsAlias(alias))
            ks.deleteEntry(alias)
    }

    inner class Signer internal constructor(private val alias: String, private val config: JavaSignerConfiguration): SignerI {
        private val jcaPrivateKey = ks.getKey(alias, config.privateKeyPassword) as PrivateKey
        private val isEC = jcaPrivateKey is ECPrivateKey
        override val publicKey: CryptoPublicKey
            get() = certificateChain.leaf.publicKey
        override val certificateChain: CertificateChain by lazy {
            ks.getCertificateChain(alias).map { X509Certificate.decodeFromDer(it.encoded) }
        }
        override val flexibleInput: Boolean get() = true
        override val nativeSignatureFormat: SignatureInputFormat get() = Digest.SHA256

        override suspend fun unlock() { /* no-op */ }

        override suspend fun unlockAndSign(data: SignatureInput) = sign(data)

        override fun sign(data: SignatureInput): CryptoSignature {
            val targetFormat = data.format ?: nativeSignatureFormat
            return Signature.getInstance("NONEwith${if (isEC) "ECDSA" else "RSA"}", config.provider).run {
                initSign(jcaPrivateKey)
                data.convertTo(targetFormat).data.forEach(this::update)
                sign()
            }.let(CryptoSignature::decodeFromDer)
        }

    }

    override fun getSignerForKey(alias: String, configure: (JavaSignerConfiguration.() -> Unit)?) =
        Signer(alias, DSL.resolve(::JavaSignerConfiguration, configure))


}
