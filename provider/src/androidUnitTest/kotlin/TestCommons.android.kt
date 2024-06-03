import at.asitplus.crypto.provider.AndroidSpecificCryptoOps
import at.asitplus.crypto.provider.PlatformCryptoOpts

actual val platformCryptoOpts: PlatformCryptoOpts
    get() = AndroidSpecificCryptoOps()