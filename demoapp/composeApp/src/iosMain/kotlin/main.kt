import androidx.compose.ui.window.ComposeUIViewController
import at.asitplus.cryptotest.App
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import platform.UIKit.UIViewController

fun MainViewController(): UIViewController = ComposeUIViewController {
    App()
}
