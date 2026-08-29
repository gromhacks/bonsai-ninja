package micro

import scala.annotation.StaticAnnotation
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}

class Audited extends StaticAnnotation

class Gateway {
  private val userService = new UserService()

  @Audited
  def handleRequest(req: HttpServletRequest, res: HttpServletResponse): Unit = {
    val token = req.getParameter("token")    // source: user input
    val action = req.getParameter("action")  // source: user input

    val user = userService.getUser(token)       // flows to SQL injection
    val result = userService.updateUser(token, action) // flows to command injection

    res.getWriter.write(s"""{"user": "${user.id}", "result": "$result"}""")
  }
}
