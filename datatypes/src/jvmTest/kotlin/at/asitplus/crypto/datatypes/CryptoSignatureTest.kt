package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.encodeToByteArray
import at.asitplus.crypto.datatypes.asn1.ensureSize
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey

class CryptoSignatureTest : FreeSpec({

    val values = (1..Byte.MAX_VALUE).toMutableSet()

    "Equals & hashCode" {
        repeat(15) {
            val first: Int = values.random().also { values.remove(it) }
            val second: Int = values.random().also { values.remove(it) }

            val ec1 = CryptoSignature.EC.fromRS(first.toBigInteger(), second.toBigInteger())
            val ec2 = CryptoSignature.EC.fromRS(first.toBigInteger(), second.toBigInteger())
            val ec3 = CryptoSignature.EC.fromRS(second.toBigInteger(), first.toBigInteger())
            val rsa1 = CryptoSignature.RSAorHMAC(first.encodeToByteArray())
            val rsa2 = CryptoSignature.RSAorHMAC(first.encodeToByteArray())
            val rsa3 = CryptoSignature.RSAorHMAC(second.encodeToByteArray())

            ec1 shouldBe ec1
            ec1 shouldBe ec2
            ec1 shouldNotBe ec3
            ec1 shouldNotBe rsa1
            rsa1 shouldBe rsa1
            rsa1 shouldBe rsa2
            rsa1 shouldNotBe rsa3

            ec1.hashCode() shouldBe ec1.hashCode()
            ec1.hashCode() shouldBe ec2.hashCode()
            ec1.hashCode() shouldNotBe ec3.hashCode()
            ec1.hashCode() shouldNotBe rsa1.hashCode()
            rsa1.hashCode() shouldBe rsa1.hashCode()
            rsa1.hashCode() shouldBe rsa2.hashCode()
            rsa1.hashCode() shouldNotBe rsa3.hashCode()

            val ec4 = ec3.guessCurve()
            ec4.scalarByteLength shouldBe ECCurve.values().minOf { it.scalarLength.bytes }
            ec4 shouldBe ec4
            ec4 shouldBe ec3
            ec4.hashCode() shouldBe ec4.hashCode()
            ec4.hashCode() shouldBe ec3.hashCode()
        }
    }

    "Length handling & Curve guessing" {
        val r = BigInteger.ONE.shl(ECCurve.SECP_521_R_1.scalarLength.bits.toInt()-1)
        val s = BigInteger.ONE
        val encoded =
            ByteArray(66) { if (it == 0) 0x01 else 0x00 } +
            ByteArray(66) { if (it == 65) 0x01 else 0x00 }

        val sig = CryptoSignature.EC.fromRS(r, s)
        shouldThrow<IllegalStateException> { sig.rawByteArray }

        val sig1 = sig.guessCurve()
        sig1 shouldBe sig
        sig1.r shouldBe sig.r
        sig1.s shouldBe sig.s
        sig1.scalarByteLength shouldBe ECCurve.SECP_521_R_1.scalarLength.bytes
        sig1.rawByteArray shouldBe encoded

        val sig2 = sig.withCurve(ECCurve.SECP_521_R_1)
        sig2 shouldBe sig1
        sig2 shouldBe sig
        sig2.r shouldBe sig.r
        sig2.s shouldBe sig.s
        sig2.scalarByteLength shouldBe sig1.scalarByteLength
        sig2.rawByteArray shouldBe encoded

        val sig3 = CryptoSignature.EC.fromRawBytes(encoded)
        sig3 shouldBe sig2
        sig3 shouldBe sig
        sig3.r shouldBe sig.r
        sig3.s shouldBe sig.s
        sig3.scalarByteLength shouldBe sig1.scalarByteLength
        sig3.rawByteArray shouldBe encoded

        val r2 = BigInteger.ONE.shl(ECCurve.values().maxOf { it.scalarLength.bits }.toInt()+1)
        shouldThrow<IllegalArgumentException> { CryptoSignature.EC.fromRS(r2, s).guessCurve() }
    }
})
