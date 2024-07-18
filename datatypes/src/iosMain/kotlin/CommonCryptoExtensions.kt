@file:OptIn(ExperimentalForeignApi::class)
import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.datatypes.RSAPadding
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Security.SecKeyAlgorithm
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA1
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA256
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA384
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA512
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA1
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA256
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA384
import platform.Security.kSecKeyAlgorithmRSASignatureMessagePSSSHA512

val SignatureAlgorithm.secKeyAlgorithm : SecKeyAlgorithm get() = when (this) {
    is SignatureAlgorithm.ECDSA -> {
        when (digest) {
            Digest.SHA1 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA1
            Digest.SHA256 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA256
            Digest.SHA384 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA384
            Digest.SHA512 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA512
            else -> throw IllegalArgumentException("Raw signing is not supported on iOS")
        }
    }
    is SignatureAlgorithm.RSA -> {
        when (padding) {
            RSAPadding.PSS -> when (digest) {
                Digest.SHA1 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA1
                Digest.SHA256 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA256
                Digest.SHA384 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA384
                Digest.SHA512 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA512
            }
            RSAPadding.PKCS1 -> when (digest) {
                Digest.SHA1 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1
                Digest.SHA256 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
                Digest.SHA384 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384
                Digest.SHA512 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
            }
        }
    }
    is SignatureAlgorithm.HMAC -> TODO("HMAC is unsupported")
}!!
