@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.crypto.provider

import kotlinx.cinterop.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionaryRef
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.kCFBooleanFalse
import platform.CoreFoundation.kCFBooleanTrue
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSData
import platform.Foundation.NSError
import platform.Foundation.create
import platform.Security.SecCopyErrorMessageString
import platform.darwin.OSStatus
import platform.posix.memcpy

@OptIn(ExperimentalForeignApi::class)
internal fun NSData.toByteArray(): ByteArray = ByteArray(length.toInt()).apply {
    usePinned {
        memcpy(it.addressOf(0), bytes, length)
    }
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
internal fun ByteArray.toNSData(): NSData = memScoped {
    NSData.create(bytes = allocArrayOf(this@toNSData), length = this@toNSData.size.toULong())
}

private fun NSError.toNiceString() =
    "[Code $code] $localizedDescription\nBecause: $localizedFailureReason\nTry: $localizedRecoverySuggestion\n${if (localizedRecoveryOptions?.isEmpty() != true) "" else "Try also:\n - ${localizedRecoveryOptions!!.joinToString("\n - ")}\n"}"

class CFCryptoOperationFailed(thing: String, osStatus: OSStatus) : CryptoOperationFailed(buildMessage(thing, osStatus)) {
    companion object {
        private fun buildMessage(thing: String, osStatus: OSStatus): String {
            val errorMessage = SecCopyErrorMessageString(osStatus, null).takeFromCF<String?>()
            return "Failed to $thing: [code $osStatus] ${errorMessage ?: "unspecified security error"}"
        }
    }
}

class CoreFoundationException(message: String): Throwable(message)
internal class corecall private constructor(val error: CPointer<CFErrorRefVar>) {
    /** Helper for calling Core Foundation functions, and bridging exceptions across.
     *
     * Usage:
     * ```
     * corecall { SomeCoreFoundationFunction(arg1, arg2, ..., error) }
     * ```
     * `error` is provided by the implicit receiver object, and will be mapped to a
     * `CoreFoundationException` if an error occurs.
     */
    companion object {
        @OptIn(BetaInteropApi::class, ExperimentalForeignApi::class)
        operator fun <T> invoke(call: corecall.()->T?) : T {
            memScoped {
                val errorH = alloc<CFErrorRefVar>()
                val result = corecall(errorH.ptr).call()
                val error = errorH.value
                when {
                    (result != null) && (error == null) -> return result
                    (result == null) && (error != null) ->
                        throw CoreFoundationException(error.takeFromCF<NSError>().toNiceString())
                    else -> throw IllegalStateException("Invalid state returned by Core Foundation call")
                }
            }
        }
    }
}
class SwiftException(message: String): Throwable(message)
internal class swiftcall private constructor(val error: CPointer<ObjCObjectVar<NSError?>>) {
    /** Helper for calling swift-objc-mapped functions, and bridging exceptions across.
     *
     * Usage:
     * ```
     * swiftcall { SwiftObj.func(arg1, arg2, .., argN, error) }
     * ```
     * `error` is provided by the implicit receiver object, and will be mapped to a
     * `SwiftException` if the swift call throws.
     */
    companion object {
        @OptIn(BetaInteropApi::class, ExperimentalForeignApi::class)
        operator fun <T> invoke(call: swiftcall.()->T?): T {
            memScoped {
                val errorH = alloc<ObjCObjectVar<NSError?>>()
                val result = swiftcall(errorH.ptr).call()
                val error = errorH.value
                when {
                    (result != null) && (error == null) -> return result
                    (result == null) && (error != null) -> throw SwiftException(error.toNiceString())
                    else -> throw IllegalStateException("Invalid state returned by Swift")
                }
            }
        }
    }
}

internal class swiftasync<T> private constructor(val callback: (T?, NSError?)->Unit) {
    /** Helper for calling swift-objc-mapped async functions, and bridging exceptions across.
     *
     * Usage:
     * ```
     * swiftasync { SwiftObj.func(arg1, arg2, .., argN, callback) }
     * ```
     * `error` is provided by the implicit receiver object, and will be mapped to a
     * `SwiftException` if the swift call throws.
     */
    companion object {
        suspend operator fun <T> invoke(call: swiftasync<T>.()->Unit): T {
            var result: T? = null
            var error: NSError? = null
            val mut = Mutex(true)
            swiftasync<T> { res, err -> result = res; error = err; mut.unlock() }.call()
            mut.withLock {
                val res = result
                val err = error
                when {
                    (res != null) && (err == null) -> return res
                    (res == null) && (err != null) -> throw SwiftException(err.toNiceString())
                    else -> throw IllegalStateException("Invalid state returned by Swift")
                }
            }
        }
    }
}

internal inline fun <reified T> Any?.giveToCF() = when(this) {
    is Boolean -> if (this) kCFBooleanTrue else kCFBooleanFalse
    is CValuesRef<*>? -> this
    else -> CFBridgingRetain(this)
} as T
internal inline fun <reified T> CFTypeRef?.takeFromCF() = CFBridgingRelease(this) as T
internal fun MemScope.cfDictionaryOf(vararg pairs: Pair<*,*>): CFDictionaryRef {
    val dict = CFDictionaryCreateMutable(null, pairs.size.toLong(), null, null)!!
    defer { CFBridgingRelease(dict) } // free it after the memscope finishes
    for (pair in pairs) {
        CFDictionaryAddValue(dict, pair.first.giveToCF(), pair.second.giveToCF())
    }
    return dict
}
