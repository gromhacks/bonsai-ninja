package micro

data class UserInfo(val id: String?, val token: String)

class UserService {
    private val authService = AuthService()

    fun getUser(token: String): UserInfo {
        val userId = authService.verifyToken(token)
        return UserInfo(id = userId, token = token)
    }

    fun updateUser(token: String, action: String): String? {
        val userId = authService.verifyToken(token)
        if (userId != null) {
            authService.runAdminCommand(userId, action)
        }
        return userId
    }
}
