package at.asitplus.cryptotest

import androidx.compose.runtime.Composable
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application

fun main() = application {
    Window(onCloseRequest = ::exitApplication, title = "KMP-Crypto Demo") {
        App()
    }
}