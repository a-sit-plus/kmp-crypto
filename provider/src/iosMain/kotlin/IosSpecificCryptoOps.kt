package at.asitplus.crypto.provider

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.io.Base64Strict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import platform.CoreFoundation.CFStringRef
import platform.LocalAuthentication.LAContext
import platform.Security.SecAccessControlCreateFlags
import platform.Security.kSecAccessControlBiometryCurrentSet
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private val AUTH_CONTAINER = Random.nextBytes(16).encodeToString(Base64Strict)


/**
 * Evaluates an [LAContext] by calling [LAContext.evaluatePolicy] on it.
 */
suspend fun LAContext.evaluate(
    laPolicy: platform.LocalAuthentication.LAPolicy,
    localizedReason: String
): KmmResult<Boolean> {
    val mut = Mutex(locked = true)
    var result: KmmResult<Boolean>? = null

    evaluatePolicy(
        policy = laPolicy,
        localizedReason
    ) { ok, err ->
        result = err?.run { KmmResult.failure(AuthenticationException("Error ${code}: $localizedDescription")) }
            ?: KmmResult.success(ok)
        mut.unlock()
    }
    mut.withLock { return result!! }
}

@OptIn(ExperimentalForeignApi::class)
class IosSpecificCryptoOps(
    val accessibilityValue: CFStringRef? = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    val secAccessControlFlags: ULong = 0uL /*this makes it empty*/,
    val authCtx: LAContext? = null,
    authContainer: AuthContainer? = null,
    vararg val keyProperties: Pair<CFStringRef?, CFStringRef?> = arrayOf()
) : PlatformCryptoOpts {

    var authContainer: AuthContainer? = authContainer
        internal set

    companion object {
        fun plain(vararg keyProperties: Pair<CFStringRef?, CFStringRef?> = arrayOf()) =
            IosSpecificCryptoOps(keyProperties = keyProperties)

        fun withSecAccessControlFlagsAndReuse(
            secAccessControlCreateFlags: SecAccessControlCreateFlags = kSecAccessControlBiometryCurrentSet,
            reuseDuration: Duration? = null,
            vararg keyProperties: Pair<CFStringRef?, CFStringRef?> = arrayOf()
        ): IosSpecificCryptoOps {
            val ctx = LAContext().apply {
                touchIDAuthenticationAllowableReuseDuration =
                    reuseDuration?.inWholeSeconds?.toDouble() ?: 0.0
            }
            val opsForUse = IosSpecificCryptoOps(authCtx = ctx)

            val opsForCreation = IosSpecificCryptoOps(
                secAccessControlFlags = secAccessControlCreateFlags,
                authCtx = ctx,
                keyProperties = keyProperties
            )

            val authContainer =
                reuseDuration?.let {
                    AuthContainer(Clock.System.now() + it, opsForUse)
                }
            opsForUse.authContainer = authContainer
            opsForCreation.authContainer = authContainer

            return opsForCreation
        }
    }
}


//TODO: this needs to be documented!
internal var IosPrivateKey.authContainer: AuthContainer?
    get() = additionalData[AUTH_CONTAINER] as AuthContainer?
    set(value) {
        if (value != null)
            additionalData[AUTH_CONTAINER] = value else
            additionalData.remove(AUTH_CONTAINER)
    }

internal fun IosPrivateKey.reAuth() {
    platformSpecifics = authContainer?.refreshAuthCtx() ?: platformSpecifics
}

class AuthContainer(
    authValidUntil: Instant,
    opsForUse: IosSpecificCryptoOps
) {

    override fun toString() = "iOS Auth Container(validUntil=$authValidUntil)"

    var authValidUntil: Instant
        private set

    var opsForUse = opsForUse
        private set

    init {
        this.authValidUntil = authValidUntil
    }

    @OptIn(ExperimentalForeignApi::class)
    internal fun refreshAuthCtx(): IosSpecificCryptoOps {
        if (authValidUntil < Clock.System.now()) {
            val touchIDAuthenticationAllowableReuseDuration =
                opsForUse.authCtx!!.touchIDAuthenticationAllowableReuseDuration
            authValidUntil =
                Clock.System.now() + touchIDAuthenticationAllowableReuseDuration.seconds
            opsForUse = IosSpecificCryptoOps(authCtx = LAContext().apply {
                this.touchIDAuthenticationAllowableReuseDuration =
                    touchIDAuthenticationAllowableReuseDuration
            })
        }
        return opsForUse.also { it.authContainer = this }
    }

    companion object {
        @OptIn(ExperimentalForeignApi::class)
        val noAuth = IosSpecificCryptoOps()
    }
}