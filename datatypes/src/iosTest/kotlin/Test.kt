import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldNotBe

class Test: FreeSpec( {

    "Wambo" {
       "wambo" shouldNotBe "Wumbo"
    }
})