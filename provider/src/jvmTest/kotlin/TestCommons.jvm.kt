import at.asitplus.crypto.provider.JvmSpecifics
import at.asitplus.crypto.provider.PlatformCryptoOpts
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyStore
import java.security.Security

actual val platformCryptoOpts: PlatformCryptoOpts = BouncyCastleProvider().let {
    Security.addProvider(it)
    JvmSpecifics(it, KeyStore.getInstance("PKCS12", "BC").apply { load(null) }, null)
}