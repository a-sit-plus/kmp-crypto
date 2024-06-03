import at.asitplus.crypto.provider.IosSpecificCryptoOps
import at.asitplus.crypto.provider.PlatformCryptoOpts
import kotlinx.cinterop.ExperimentalForeignApi


actual val platformCryptoOpts: PlatformCryptoOpts
    get() = @OptIn(ExperimentalForeignApi::class) IosSpecificCryptoOps()