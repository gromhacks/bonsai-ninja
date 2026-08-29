// Receiver-type audit fixture (Kotlin).
// `f` is typed `File` from the constructor. The shipped rule
// `kotlin.path.file_readtext` matches `[File, readText]`. Without
// receiver-type resolution, `f.readText()` won't match.
import java.io.File

fun handle() {
    // POSITIVE
    val tainted = System.getenv("PATH_INPUT") ?: ""
    val f = File("/data", tainted)
    f.readText()
}
