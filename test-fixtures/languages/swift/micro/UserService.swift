import Foundation

struct UserInfo {
    let id: String?
    let token: String
}

class UserService {
    let authService = AuthService()

    func getUser(token: String) -> UserInfo {
        let userId = authService.verifyToken(token)
        return UserInfo(id: userId, token: token)
    }

    func updateUser(token: String, action: String) -> String? {
        let userId = authService.verifyToken(token)
        if let uid = userId {
            authService.runAdminCommand(uid, action)
        }
        return userId
    }
}
