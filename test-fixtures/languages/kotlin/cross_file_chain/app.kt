// Cross-file argument flow audit fixture (Kotlin).
fun handler() {
    // POSITIVE
    val user = System.getenv("CMD") ?: ""
    runPipeline(user)
}

fun handlerSplit() {
    // POSITIVE
    val user = System.getenv("FROM") ?: ""
    val flag = System.getenv("FLAG") ?: ""
    runPipeline("$user:$flag")
}
