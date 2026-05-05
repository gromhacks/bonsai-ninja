using System.Collections.Generic;

namespace Micro
{
    public class UserService
    {
        private readonly AuthService _authService = new AuthService();

        public Dictionary<string, string> GetUser(string token)
        {
            var userId = _authService.VerifyToken(token);
            return new Dictionary<string, string>
            {
                { "id", userId },
                { "token", token }
            };
        }

        public string UpdateUser(string token, string action)
        {
            var userId = _authService.VerifyToken(token);
            if (userId != null)
            {
                _authService.RunAdminCommand(userId, action);
            }
            return userId;
        }
    }
}
