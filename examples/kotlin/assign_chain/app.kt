// Assignment-chain audit fixture (Kotlin).
import javax.servlet.http.HttpServletRequest

const val CONST_OK = "ls /tmp"

fun passthrough(x: String): String = x
fun wrap(x: String): String = "wrapped:$x"
fun combine(acc: String, item: String): String = "$acc:$item"

class Bag {
    var payload: String = ""
}

fun chainSimple(req: HttpServletRequest) {
    // POSITIVE
    val tmp = req.getParameter("c1")
    Runtime.getRuntime().exec(tmp)
}

fun chainMultiHop(req: HttpServletRequest) {
    // POSITIVE
    val t1 = req.getParameter("c2")
    val t2 = passthrough(t1)
    val t3 = wrap(t2)
    val t4 = passthrough(t3)
    Runtime.getRuntime().exec(t4)
}

fun chainBranchJoin(req: HttpServletRequest, cond: Boolean) {
    // POSITIVE
    val t = if (cond) req.getParameter("c3") else "safe-static"
    Runtime.getRuntime().exec(t)
}

fun chainLoopCarried(req: HttpServletRequest, items: List<String>) {
    // POSITIVE
    var acc = req.getParameter("c4")
    for (item in items) {
        acc = combine(acc, item)
    }
    Runtime.getRuntime().exec(acc)
}

fun chainFieldWrite(req: HttpServletRequest) {
    // POSITIVE
    val bag = Bag()
    bag.payload = req.getParameter("c5")
    Runtime.getRuntime().exec(bag.payload)
}

fun chainSubscriptWrite(req: HttpServletRequest) {
    // POSITIVE
    val cmds = mutableMapOf<String, String>()
    cmds["x"] = req.getParameter("c6")
    Runtime.getRuntime().exec(cmds["x"]!!)
}

fun chainCleanConstant(req: HttpServletRequest) {
    // NEGATIVE
    val unused = req.getParameter("ignored")
    Runtime.getRuntime().exec(CONST_OK)
}

fun chainCrossFile(req: HttpServletRequest) {
    // POSITIVE
    val t = req.getParameter("c9")
    runInOtherFile(t)
}
