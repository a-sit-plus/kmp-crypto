package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.misc.BitLength
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class BitLengthTest : FreeSpec({
    "Small toy values" {
        BitLength(0u).run {
            this shouldBe BitLength(0)
            bits shouldBe 0u
            bytes shouldBe 0u
            bitSpacing shouldBe 0u
        }

        BitLength(1u).run {
            bits shouldBe 1u
            bytes shouldBe 1u
            bitSpacing shouldBe 7u
        }

        BitLength(6u).run {
            bits shouldBe 6u
            bytes shouldBe 1u
            bitSpacing shouldBe 2u
        }
    }
    "ECDSA values" {
        BitLength(256u).run {
            bits shouldBe 256u
            bytes shouldBe 32u
            bitSpacing shouldBe 0u
        }
        BitLength(384u).run {
            bits shouldBe 384u
            bytes shouldBe 48u
            bitSpacing shouldBe 0u
        }
        BitLength(521u).run {
            bits shouldBe 521u
            bytes shouldBe 66u
            bitSpacing shouldBe 7u
        }
    }
})
