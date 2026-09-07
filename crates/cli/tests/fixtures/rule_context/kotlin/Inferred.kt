import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.client.RestTemplate
class Inferred {
    fun request(@RequestParam next: String) {
        val client = RestTemplate()
        client.getForObject(next, String::class.java)
    }
}
