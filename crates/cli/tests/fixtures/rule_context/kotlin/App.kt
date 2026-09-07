import org.springframework.web.bind.annotation.RequestParam
import okhttp3.HttpUrl
import org.springframework.web.client.RestTemplate
class App {
    fun encoded(@RequestParam next: String, client: RestTemplate) {
        client.getForObject(HttpUrl.parse(next).toString(), String::class.java)
    }
    fun direct(@RequestParam next: String, client: RestTemplate) {
        client.getForObject(next, String::class.java)
    }
}
