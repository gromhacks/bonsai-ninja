fun unsanitized() {
    val t = System.getenv("CMD") ?: ""
    Runtime.getRuntime().exec(t)
}

fun sanitized() {
    val t = System.getenv("CMD") ?: ""
    val safe = t.replace(Regex("[^A-Za-z0-9_-]"), "")
    Runtime.getRuntime().exec(safe)
}
