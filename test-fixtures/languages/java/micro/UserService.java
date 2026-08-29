package micro;

import java.util.HashMap;
import java.util.Map;

public class UserService {
    private AuthService authService;

    public UserService() throws Exception {
        this.authService = new AuthService();
    }

    public Map<String, String> getUser(String token) throws Exception {
        String userId = authService.verifyToken(token);
        Map<String, String> user = new HashMap<>();
        user.put("id", userId);
        user.put("token", token);
        return user;
    }

    public String updateUser(String token, String action) throws Exception {
        String userId = authService.verifyToken(token);
        if (userId != null) {
            authService.runAdminCommand(userId, action);
        }
        return userId;
    }
}
