import 'auth_service.dart';

int? getUser(String token) {
  return verifyToken(token);
}

int? updateUser(String token, String action) {
  var userId = verifyToken(token);
  if (userId != null) {
    runAdminCommand(userId, action);
  }
  return userId;
}
