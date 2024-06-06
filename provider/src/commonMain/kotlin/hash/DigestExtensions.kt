package at.asitplus.crypto.provider.hash

import at.asitplus.crypto.datatypes.Digest
import org.kotlincrypto.hash.sha1.SHA1
import org.kotlincrypto.hash.sha2.SHA256
import org.kotlincrypto.hash.sha2.SHA384
import org.kotlincrypto.hash.sha2.SHA512

operator fun Digest.invoke(): org.kotlincrypto.core.digest.Digest = when(this) {
    Digest.SHA1 -> SHA1()
    Digest.SHA256 -> SHA256()
    Digest.SHA384 -> SHA384()
    Digest.SHA512 -> SHA512()
}
inline fun Digest.digest(data: Sequence<ByteArray>) = this().also { data.forEach(it::update) }.digest()
inline fun Digest.digest(bytes: ByteArray) = this().digest(bytes)
