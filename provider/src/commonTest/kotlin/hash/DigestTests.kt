package hash

import at.asitplus.crypto.datatypes.Digest
import at.asitplus.crypto.provider.hash.digest
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

class DigestTests: FreeSpec({
    data class TestSpec(val data: String, val reps: Int, val note: String, val ref: (Digest)->String)
    withData(nameFn=TestSpec::note, listOf(
        TestSpec("abc",1,"'abc', the bit string (0x)616263 of length 24 bits") { when(it) {
            Digest.SHA1 -> "a9993e364706816aba3e25717850c26c9cd0d89d"
            Digest.SHA256 -> "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            Digest.SHA384 -> "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
            Digest.SHA512 -> "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        } },
        TestSpec("",1,"the empty string '', a bit string of length 0") { when(it) {
            Digest.SHA1 -> "da39a3ee5e6b4b0d3255bfef95601890afd80709"
            Digest.SHA256 -> "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            Digest.SHA384 -> "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
            Digest.SHA512 -> "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        } },
        TestSpec("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1, "length 448 bits") { when(it) {
            Digest.SHA1 -> "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
            Digest.SHA256 -> "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            Digest.SHA384 -> "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"
            Digest.SHA512 -> "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
        } },
        TestSpec("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1, "length 896 bits") { when(it) {
            Digest.SHA1 -> "a49b2446a02c645bf419f995b67091253a04a259"
            Digest.SHA256 -> "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
            Digest.SHA384 -> "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
            Digest.SHA512 -> "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        } },
        TestSpec("a", 1000000, "one million (1,000,000) repetitions of the character 'a' (0x61)") { when(it) {
            Digest.SHA1 -> "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
            Digest.SHA256 -> "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
            Digest.SHA384 -> "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
            Digest.SHA512 -> "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
        } },
        TestSpec("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216, "the extremely-long message 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno' repeated 16,777,216 times: a bit string of length 2^{33} bits (~1 GB)") { when(it) {
            Digest.SHA1 -> "7789f0c9ef7bfc40d93311143dfbe69e2017f592"
            Digest.SHA256 -> "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"
            Digest.SHA384 -> "5441235cc0235341ed806a64fb354742b5e5c02a3c5cb71b5f63fb793458d8fdae599c8cd8884943c04f11b31b89f023"
            Digest.SHA512 -> "b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086"
        }}
    )) { test ->
        withData(Digest.entries) { digest ->
            val rawData = test.data.encodeToByteArray()
            @OptIn(ExperimentalStdlibApi::class)
            val ref = test.ref(digest).hexToByteArray()
            val result = if (test.reps == 1) digest.digest(rawData)
                         else digest.digest(sequence {
                            (1..test.reps).forEach { yield(rawData) }
                         })
            result shouldBe ref
        }
    }
})
