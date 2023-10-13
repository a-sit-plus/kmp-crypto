package at.asitplus.crypto.datatypes.asn1

import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.checkAll

class Asn1IntegerTest : FreeSpec(
    {
        "Ans1 Number encoding" - {

            withData(15253481L, -1446230472L, 0L, 1L, -1L, -2L, -9994587L, 340281555L) {
                val bytes = (it).encodeToByteArray()

                val long = Long.decodeFromDer(bytes)

                long shouldBe it
            }


            "longs" - {
                checkAll(iterations = 15000, Arb.long()) {
                    val seq = asn1Sequence { long { it } }
                    val decoded = (seq.nextChild() as Asn1Primitive).readLong()
                    decoded shouldBe it
                }
            }

            "ints" - {
                checkAll(iterations = 15000, Arb.int()) {
                    val seq = asn1Sequence { int { it } }
                    val decoded = (seq.nextChild() as Asn1Primitive).readInt()
                    decoded shouldBe it
                }
            }

        }
    }
)