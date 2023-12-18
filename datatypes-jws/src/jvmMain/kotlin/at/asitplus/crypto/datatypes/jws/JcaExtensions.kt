package at.asitplus.crypto.datatypes.jws

val JweEncryption.jcaName
    get() = when (this) {
        JweEncryption.A256GCM -> "AES/GCM/NoPadding"
    }

val JweEncryption.jcaKeySpecName
    get() = when (this) {
        JweEncryption.A256GCM -> "AES"
    }

val JweAlgorithm.jcaName
    get() = when (this) {
        JweAlgorithm.ECDH_ES -> "ECDH"
        JweAlgorithm.RSA_OAEP_256 -> "RSA-OAEP-256"
        JweAlgorithm.RSA_OAEP_384 -> "RSA-OAEP-384"
        JweAlgorithm.RSA_OAEP_512 -> "RSA-OAEP-512"
    }