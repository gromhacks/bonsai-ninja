import 'dart:io';
import 'package:sqflite/sqflite.dart';

late Database authDb;

int? verifyToken(String token) {
  var query = "SELECT user_id FROM tokens WHERE token = '$token'";
  // sink: SQL injection via string interpolation
  authDb.rawQuery(query);
  return 1;
}

void runAdminCommand(int userId, String cmd) {
  // sink: command injection — cmd is concatenated into the shell
  Process.runSync('sh', ['-c', 'notify-admin $cmd']);
}
