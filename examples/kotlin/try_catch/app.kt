fun taintedThroughTry() {
    val t = try {
        System.getenv("CMD") ?: ""
    } catch (e: Exception) {
        ""
    }
    Runtime.getRuntime().exec(t)
}
