package micro

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

annotation class Audited

class Gateway {
    private val userService = UserService()

    @Audited
    fun handleRequest(req: HttpServletRequest, res: HttpServletResponse) {
        val token = req.getParameter("token")    // source: user input
        val action = req.getParameter("action")  // source: user input

        val user = userService.getUser(token)       // flows to SQL injection
        val result = userService.updateUser(token, action) // flows to command injection

        res.writer.write("""{"user": "${user.id}", "result": "$result"}""")
    }
}
