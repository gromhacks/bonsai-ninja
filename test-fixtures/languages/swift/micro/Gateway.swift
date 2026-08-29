import Foundation

class Gateway {
    let userService = UserService()

    func handleRequest(queryParams: [String: String]) -> String {
        let token = queryParams["token"]!    // source: user input
        let action = queryParams["action"]!  // source: user input

        let user = userService.getUser(token: token)         // flows to SQL injection
        let result = userService.updateUser(token: token, action: action) // flows to command injection

        return "{\"user\": \"\(user.id ?? "null")\", \"result\": \"\(result ?? "null")\"}"
    }
}
