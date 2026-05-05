package micro

case class UserInfo(id: Option[String], token: String)

class UserService {
  private val authService = new AuthService()

  def getUser(token: String): UserInfo = {
    val userId = authService.verifyToken(token)
    UserInfo(id = userId, token = token)
  }

  def updateUser(token: String, action: String): Option[String] = {
    val userId = authService.verifyToken(token)
    userId.foreach { uid =>
      authService.runAdminCommand(uid, action)
    }
    userId
  }
}
