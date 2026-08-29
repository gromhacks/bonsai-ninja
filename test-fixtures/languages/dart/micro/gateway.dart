import 'user_service.dart';

Map<String, dynamic> handleRequest(String token, String action) {
  var user = getUser(token);
  var result = updateUser(token, action);
  return {"user": user, "result": result};
}
