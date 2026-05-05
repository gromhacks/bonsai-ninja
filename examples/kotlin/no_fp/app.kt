const val CONST_OK = "ls /tmp"

fun decoy() {
    val _unused = System.getenv("IGNORED") ?: ""
    Runtime.getRuntime().exec(CONST_OK)
}

fun unrelatedChain(): String {
    val a = "hello"
    return a.uppercase()
}
