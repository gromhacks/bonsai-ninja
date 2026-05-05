// Complex multi-construct Dart fixture exercising branches, loops,
// try/catch, async/await, and classes.
import 'dart:io';
import 'dart:async';

class UserRepository {
  Map<int, String> users = {};

  String? findUser(int id) {
    if (users.containsKey(id)) {
      return users[id];
    }
    return null;
  }

  Future<bool> loadAllUsers() async {
    try {
      for (var i = 0; i < 10; i++) {
        users[i] = "user_$i";
      }
      return true;
    } catch (e) {
      print("load failed: $e");
      return false;
    }
  }
}

String escapeSQL(String input) {
  return input.replaceAll("'", "''");
}

void dispatchToken(String token) {
  if (token.isEmpty) {
    return;
  }
  if (token.startsWith("admin_")) {
    runAdmin(token);
  } else {
    runUser(token);
  }
}

void processBatch(List<String> tokens) {
  for (var token in tokens) {
    dispatchToken(token);
  }
}

void runAdmin(String token) {
  Process.runSync('sh', ['-c', 'admin-task $token']);
}

void runUser(String token) {
  Process.runSync('sh', ['-c', 'user-task $token']);
}

Future<String> asyncFetch(String key) async {
  await Future.delayed(Duration(milliseconds: 10));
  return "value:$key";
}
