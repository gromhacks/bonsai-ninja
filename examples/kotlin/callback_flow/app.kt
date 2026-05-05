fun executor(cmd: String) {
    Runtime.getRuntime().exec(cmd)
}

fun run(cb: (String) -> Unit, value: String) {
    cb(value)
}

fun passToCallback() {
    val t = System.getenv("CMD") ?: ""
    run(::executor, t)
}
