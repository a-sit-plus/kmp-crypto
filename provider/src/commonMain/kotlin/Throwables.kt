package at.asitplus.crypto.provider

import at.asitplus.crypto.datatypes.CryptoAlgorithm

sealed class CryptoException(msg: String?, cause: Throwable? = null) : Throwable(msg, cause)

/**
 * The provided [alg] is unsupported. Currently, ony EC is supported.
 * Attestation is only supported on iOS and Android.
 */
class UnsupportedAlgorithmException(val alg: CryptoAlgorithm, msg: String) : CryptoException(msg)

/**
 * The authentication procedure to access protected key material did not succeed.
 */
class AuthenticationException(msg: String) : CryptoException(msg)

/**
 * The provided [platformCryptoOpts] to not fit the requested operation
 */
//class InvalidParameterException(val platformCryptoOpts: PlatformCryptoOpts?, msg: String) : CryptoException(msg)

/**
 * The cryptographic operation did not succeed.
 */
class CryptoExecutionException(msg: String?, cause: Throwable? = null) : CryptoException(msg, cause)

/**
 * Transformation of cryptographic material failed (e.g. ASN.1 encoding/decoding failed)
 */
class EncodingException(msg: String?, cause: Throwable?) : CryptoException(msg, cause)

/**
 * The requested cryptographic object was not found
 */
class CryptoObjectNotFoundException(msg: String) : CryptoException(msg)