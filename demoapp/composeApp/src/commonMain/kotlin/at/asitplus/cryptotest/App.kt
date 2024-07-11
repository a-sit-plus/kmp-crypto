package at.asitplus.cryptotest

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.asn1.Asn1Element
import at.asitplus.crypto.datatypes.asn1.parse
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.provider.CryptoPrivateKey
import at.asitplus.crypto.provider.CryptoKeyPair
import at.asitplus.crypto.provider.TbaKey
import at.asitplus.crypto.provider.public
import at.asitplus.cryptotest.theme.AppTheme
import at.asitplus.cryptotest.theme.LocalThemeIsDark
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.ktor.util.decodeBase64Bytes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

val SAMPLE_CERT_CHAIN = listOf(
    "MIIDljCCAxygAwIBAgISBAkE/SHlMi5J8uQGoGCZBnhSMAoGCCqGSM49BAMDMDIx\n" +
            "CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF\n" +
            "MTAeFw0yNDAzMTMyMDQ2MjZaFw0yNDA2MTEyMDQ2MjVaMBwxGjAYBgNVBAMTEXN0\n" +
            "YWNrb3ZlcmZsb3cuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENMSrkEQf\n" +
            "2x8dEAh73snPfgxMIK+VYUyIIYA+NuRhhyZuL2ZV9N4ZUibe/eEad3Y8HND3Kuz/\n" +
            "2vxFzJvR8nlKSqOCAiYwggIiMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggr\n" +
            "BgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUeQJ7DtZq\n" +
            "02WUcs0cMmOa/eJEuxcwHwYDVR0jBBgwFoAUWvPtK/w2wjd5uVIw6lRvz1XLLqww\n" +
            "VQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vZTEuby5sZW5jci5v\n" +
            "cmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9lMS5pLmxlbmNyLm9yZy8wMQYDVR0RBCow\n" +
            "KIITKi5zdGFja292ZXJmbG93LmNvbYIRc3RhY2tvdmVyZmxvdy5jb20wEwYDVR0g\n" +
            "BAwwCjAIBgZngQwBAgEwggECBgorBgEEAdZ5AgQCBIHzBIHwAO4AdQA7U3d1Pi25\n" +
            "gE6LMFsG/kA7Z9hPw/THvQANLXJv4frUFwAAAY45x+icAAAEAwBGMEQCICqwZ2ic\n" +
            "dHGogPX6/nRhsJ2AMWROA2MkZ+zZ/8dvzaCoAiBDqexmj0syXLpaCAhZ7Jjps+QN\n" +
            "UHsHX8F/VE2eQ4fmdAB1AEiw42vapkc0D+VqAvqdMOscUgHLVt0sgdm7v6s52IRz\n" +
            "AAABjjnH6KcAAAQDAEYwRAIgRB4bHal+3msYGbblbfHhWcVm+95f7fkEWQabASE2\n" +
            "qycCIFJ/P1mixU1zSN6L/hZSvP8RTgUxy/xvbfrcF8giDNA/MAoGCCqGSM49BAMD\n" +
            "A2gAMGUCMDe8nbCNF3evyvyGNxKOaScHhZ9ScGi5zeEo4ogiY6f25FV3wzfE2enB\n" +
            "3QUOvZLJbgIxAIc//kc6UgMSKC+FNL3LM3c4avx9jaKZwUvlcOvxrSExYvnmxqrA\n" +
            "jC2PPx8F/hF+ww==",
    "MIICxjCCAk2gAwIBAgIRALO93/inhFu86QOgQTWzSkUwCgYIKoZIzj0EAwMwTzEL\n" +
            "MAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNo\n" +
            "IEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDIwHhcNMjAwOTA0MDAwMDAwWhcN\n" +
            "MjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5j\n" +
            "cnlwdDELMAkGA1UEAxMCRTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQkXC2iKv0c\n" +
            "S6Zdl3MnMayyoGli72XoprDwrEuf/xwLcA/TmC9N/A8AmzfwdAVXMpcuBe8qQyWj\n" +
            "+240JxP2T35p0wKZXuskR5LBJJvmsSGPwSSB/GjMH2m6WPUZIvd0xhajggEIMIIB\n" +
            "BDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMB\n" +
            "MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFFrz7Sv8NsI3eblSMOpUb89V\n" +
            "yy6sMB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEB\n" +
            "BCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzAnBgNVHR8E\n" +
            "IDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYG\n" +
            "Z4EMAQIBMA0GCysGAQQBgt8TAQEBMAoGCCqGSM49BAMDA2cAMGQCMHt01VITjWH+\n" +
            "Dbo/AwCd89eYhNlXLr3pD5xcSAQh8suzYHKOl9YST8pE9kLJ03uGqQIwWrGxtO3q\n" +
            "YJkgsTgDyj2gJrjubi1K9sZmHzOa25JK1fUpE8ZwYii6I4zPPS/Lgul/",
    "MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw\n" +
            "CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg\n" +
            "R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00\n" +
            "MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT\n" +
            "ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw\n" +
            "EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW\n" +
            "+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9\n" +
            "ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T\n" +
            "AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI\n" +
            "zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW\n" +
            "tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1\n" +
            "/q4AaOeMSQ+2b1tbFfLn"
).map { X509Certificate.decodeFromDer(it.replace("\n", "").decodeBase64Bytes()) }


const val ALIAS = "Bartschlüssel"

val context = newSingleThreadContext("crypto").also { Napier.base(DebugAntilog()) }


@OptIn(ExperimentalStdlibApi::class, ExperimentalCoroutinesApi::class)
@Composable
internal fun App() {

    AppTheme {
        var attestation by remember { mutableStateOf(false) }
        var biometricAuth by remember { mutableStateOf(" Disabled") }
        var selectedIndex by remember { mutableStateOf(0) }
        val algos = listOf(CryptoAlgorithm.ES256, CryptoAlgorithm.ES384, CryptoAlgorithm.ES512)
        var inputData by remember { mutableStateOf("Foo") }
        var currentKey by remember { mutableStateOf<KmmResult<TbaKey>?>(null) }
        var currentKeyStr by remember { mutableStateOf("<none>") }
        var signingPossible by remember { mutableStateOf(currentKey?.isSuccess == true) }
        var signatureData by remember { mutableStateOf("") }
        var certData by remember { mutableStateOf("") }
        var canGenerate by remember { mutableStateOf(true) }

        var genText by remember { mutableStateOf("Generate Key") }

        Column(modifier = Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)) {

            Row(
                horizontalArrangement = Arrangement.Center
            ) {
                Text(
                    text = "KMP Crypto Demo",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(
                        top = 16.dp,
                        start = 16.dp,
                        end = 16.dp,
                        bottom = 0.dp
                    )
                )

                Spacer(modifier = Modifier.weight(1.0f))

                var isDark by LocalThemeIsDark.current
                IconButton(
                    onClick = { isDark = !isDark }
                ) {
                    Icon(
                        modifier = Modifier.padding(8.dp).size(20.dp),
                        imageVector = if (isDark) Icons.Default.LightMode else Icons.Default.DarkMode,
                        contentDescription = null
                    )
                }
            }

            var displayedKeySize by remember { mutableStateOf(" ▼ " + algos[selectedIndex]) }
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row {
                    Text(
                        "Attestation",
                        modifier = Modifier.padding(top = 11.dp)
                    )
                    Checkbox(checked = attestation,
                        modifier = Modifier.wrapContentSize(Alignment.TopStart).padding(0.dp),
                        onCheckedChange = {
                            attestation = it
                            if (attestation) {
                                selectedIndex = 0
                                displayedKeySize = " ▽ " + algos[selectedIndex]
                            } else {
                                displayedKeySize = " ▼ " + algos[selectedIndex]
                            }
                        })
                }
                Row {
                    Text(
                        "Biometric Auth",
                        modifier = Modifier.padding(
                            start = 0.dp,
                            top = 12.dp,
                            end = 4.dp,
                            bottom = 0.dp
                        )


                    )

                    var expanded by remember { mutableStateOf(false) }
                    Box(
                        modifier = Modifier.wrapContentSize(Alignment.TopStart).padding(top = 12.dp)
                            .background(MaterialTheme.colorScheme.primary)
                    ) {

                        Text(
                            biometricAuth,
                            modifier = Modifier.align(Alignment.BottomStart).width(78.dp)
                                .clickable(onClick = {
                                    expanded = true

                                }),
                            color = MaterialTheme.colorScheme.onPrimary

                        )
                        DropdownMenu(
                            expanded = expanded,
                            onDismissRequest = {
                                expanded = false
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            listOf(
                                " Disabled",
                                " 0s",
                                " 10s",
                                " 20s",
                                " 60s"
                            ).forEachIndexed { _, s ->
                                DropdownMenuItem(text = { Text(text = s) },
                                    onClick = {
                                        expanded = false
                                        biometricAuth = s
                                    })
                            }
                        }
                    }
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Key Type", modifier = Modifier.padding(horizontal = 16.dp))
                var expanded by remember { mutableStateOf(false) }
                Box(
                    modifier = Modifier.fillMaxWidth().wrapContentSize(Alignment.TopStart)
                        .padding(horizontal = 16.dp).background(MaterialTheme.colorScheme.primary)
                ) {

                    Text(
                        displayedKeySize,
                        modifier = Modifier.fillMaxWidth().align(Alignment.TopStart)
                            .clickable(onClick = {
                                if (!attestation) {
                                    expanded = true
                                    displayedKeySize = " ▲ " + algos[selectedIndex]
                                }
                            }),
                        color = MaterialTheme.colorScheme.onPrimary

                    )
                    DropdownMenu(
                        expanded = expanded,
                        onDismissRequest = {
                            expanded = false
                            displayedKeySize = " ▼ " + algos[selectedIndex]
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        algos.forEachIndexed { index, s ->
                            DropdownMenuItem(text = { Text(text = s.toString()) },
                                onClick = {
                                    selectedIndex = index
                                    expanded = false
                                    displayedKeySize = " ▼ " + algos[selectedIndex]
                                })
                        }
                    }
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Button(
                    enabled = canGenerate,
                    onClick = {
                        CoroutineScope(context).launch {
                            canGenerate = false
                            genText = "Generating. Please wait…"
                            currentKey = generateKey(
                                algos[selectedIndex],
                                if (attestation) Random.nextBytes(16) else null,
                                runCatching {
                                    biometricAuth.substringBefore("s").trim().toInt()
                                }.getOrNull()?.seconds
                            ).also { it.exceptionOrNull()?.printStackTrace() }

                            //just to check
                            loadPubKey().let { Napier.w { "PubKey retrieved from native: $it" } }

                            currentKeyStr = currentKey!!.map {
                                it.first.toString() + ": " +
                                        it.second.joinToString {
                                            runCatching {
                                                Asn1Element.parse(it).prettyPrint()
                                            }.getOrDefault(
                                                it.toHexString(
                                                    HexFormat.UpperCase
                                                )
                                            )
                                        }
                            }.toString()
                            signingPossible = currentKey?.isSuccess ?: false
                            Napier.w { "Signing possible: ${currentKey?.isSuccess}" }
                            canGenerate = true
                            genText = "Generate Key"
                        }
                    },
                    modifier = Modifier.padding(start = 16.dp)
                ) {
                    Text(genText)
                }

                Button(
                    enabled = canGenerate,
                    onClick = {
                        CoroutineScope(context).launch {
                            canGenerate = false
                            genText = "Loading Key. Please wait…"
                            loadPrivateKey().let {
                                Napier.w { "Priv retrieved from native: $it" }
                                currentKey = it.map {
                                    TbaKey(it, listOf())

                                }
                                currentKeyStr = currentKey.toString()

                            }

                            //just to check
                            loadPubKey().let { Napier.w { "PubKey retrieved from native: $it" } }
                            canGenerate = true
                            genText = "Generate New Key"
                            signingPossible = currentKey?.isSuccess ?: false
                        }
                    },
                    modifier = Modifier.padding(end = 16.dp)
                ) {
                    Text("Load Private Key")
                }

            }
            OutlinedTextField(value = currentKeyStr,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                minLines = 1,
                maxLines = 5,
                textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                readOnly = true, onValueChange = {}, label = { Text("Current Key") })


            OutlinedTextField(value = inputData,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                enabled = true,
                minLines = 1,
                maxLines = 2,
                textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                onValueChange = { inputData = it },
                label = { Text("Data to be signed") })

            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Button(
                    onClick = {

                        Napier.w { "input: $inputData" }
                        Napier.w { "signinKey: $currentKey" }
                        CoroutineScope(context).launch {
                            sign(
                                inputData.encodeToByteArray(),
                                when ((currentKey!!.getOrThrow().first.public as CryptoPublicKey.EC).curve.keyLengthBits) {
                                    256u -> CryptoAlgorithm.ES256

                                    384u -> CryptoAlgorithm.ES384

                                    else -> CryptoAlgorithm.ES512
                                },
                                currentKey!!.getOrThrow().first.first
                            ).map { signatureData = it.encodeToTlv().prettyPrint() }
                        }

                    },

                    enabled = signingPossible
                ) {
                    Text("Sign")
                }

                Button(
                    onClick = {
                        Napier.w { "crt: $currentKey" }
                        CoroutineScope(context).launch {
                            storeCertChain().let {
                                Napier.w { "STORE: $it" }
                            }

                            val loaded = getCertChain().also {
                                Napier.w { "LOADED: $it" }
                                certData = it.toString()
                            }
                            Napier.w { "chains are equal: " + (loaded.getOrNull() == SAMPLE_CERT_CHAIN) }
                        }
                    },
                ) {
                    Text("Store and Load Cert")
                }
            }

            OutlinedTextField(value = signatureData,
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                minLines = 1,
                textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                readOnly = true, onValueChange = {}, label = { Text("Detached Signature") })

            OutlinedTextField(value = certData,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                minLines = 1,
                textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                readOnly = true,
                onValueChange = {},
                label = { Text("Certificate Chain from KeyStore") })
        }
    }
}

internal expect suspend fun generateKey(
    alg: CryptoAlgorithm,
    attestation: ByteArray?,
    withBiometricAuth: Duration?,

    ): KmmResult<TbaKey>

internal expect suspend fun sign(
    data: ByteArray,
    alg: CryptoAlgorithm,
    signingKey: CryptoPrivateKey
): KmmResult<CryptoSignature>

internal expect suspend fun loadPubKey(): KmmResult<CryptoPublicKey>

internal expect suspend fun loadPrivateKey(): KmmResult<CryptoKeyPair>

internal expect suspend fun storeCertChain(): KmmResult<Unit>
internal expect suspend fun getCertChain(): KmmResult<List<X509Certificate>>