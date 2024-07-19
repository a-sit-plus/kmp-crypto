package at.asitplus.crypto.provider

sealed class CryptoException(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
open class CryptoOperationFailed(message: String) : CryptoException(message)

open class UnsupportedCryptoException(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

class UnlockFailed(message: String? = null, cause: Throwable? = null) : Throwable(message, cause)
