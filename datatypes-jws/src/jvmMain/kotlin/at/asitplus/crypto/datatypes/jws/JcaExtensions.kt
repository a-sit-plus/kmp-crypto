package at.asitplus.crypto.datatypes.jws

val JweEncryption.jcaName
    get() = when (this) {
        JweEncryption.A128GCM, JweEncryption.A192GCM, JweEncryption.A256GCM -> "AES/GCM/NoPadding"
        JweEncryption.A128CBC_HS256, JweEncryption.A192CBC_HS384, JweEncryption.A256CBC_HS512 -> "AES/CBC/PKCS5Padding"
    }

val JweEncryption.isAuthenticatedEncryption
    get() = when (this) {
        JweEncryption.A128GCM, JweEncryption.A192GCM, JweEncryption.A256GCM -> true
        JweEncryption.A128CBC_HS256, JweEncryption.A192CBC_HS384, JweEncryption.A256CBC_HS512 -> false
    }

val JweEncryption.jcaKeySpecName
    get() = when (this) {
        JweEncryption.A128GCM, JweEncryption.A192GCM, JweEncryption.A256GCM -> "AES"
        JweEncryption.A128CBC_HS256, JweEncryption.A192CBC_HS384, JweEncryption.A256CBC_HS512 -> "AES"
    }

val JweAlgorithm.jcaName:String?
    get() = when (this) {
        JweAlgorithm.ECDH_ES -> "ECDH"
        JweAlgorithm.A128KW, JweAlgorithm.A192KW, JweAlgorithm.A256KW -> "AES"
        JweAlgorithm.RSA_OAEP_256, JweAlgorithm.RSA_OAEP_384, JweAlgorithm.RSA_OAEP_512 -> "RSA/ECB/OAEPPadding"
        is JweAlgorithm.UNKNOWN -> null
    }