using Microsoft.AspNetCore.Http;
using System.Collections.Generic;

namespace Micro
{
    public class AuditedAttribute : System.Attribute { }

    public class Gateway
    {
        private readonly UserService _userService = new UserService();

        [Audited]
        public string HandleRequest(HttpRequest req)
        {
            var token = req.Query["token"].ToString();    // source: user input
            var action = req.Query["action"].ToString();  // source: user input

            var user = _userService.GetUser(token);       // flows to SQL injection
            var result = _userService.UpdateUser(token, action); // flows to command injection

            return $"{{\"user\": \"{user[\"id\"]}\", \"result\": \"{result}\"}}";
        }
    }
}
