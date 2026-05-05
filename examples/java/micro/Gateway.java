package micro;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@Retention(RetentionPolicy.RUNTIME)
@interface Audited {}

public class Gateway {
    private UserService userService;

    public Gateway() throws Exception {
        this.userService = new UserService();
    }

    @Audited
    public void handleRequest(HttpServletRequest req, HttpServletResponse res) throws Exception {
        String token = req.getParameter("token");    // source: user input
        String action = req.getParameter("action");  // source: user input

        Map<String, String> user = userService.getUser(token);      // flows to SQL injection
        String result = userService.updateUser(token, action);  // flows to command injection

        res.getWriter().write("{\"user\": " + user + ", \"result\": \"" + result + "\"}");
    }
}
