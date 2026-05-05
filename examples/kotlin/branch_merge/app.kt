fun taintOneLeg(cond: Boolean) {
    val x = if (cond) System.getenv("CMD") ?: "" else "safe-static"
    Runtime.getRuntime().exec(x)
}

fun taintOverwritten(cond: Boolean) {
    var x = System.getenv("CMD") ?: ""
    x = if (cond) "clean-then" else "clean-else"
    Runtime.getRuntime().exec(x)
}
