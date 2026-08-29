import 'dart:io';

void executor(String cmd) {
  Process.runSync(cmd, []);
}

void runCb(void Function(String) cb, String value) {
  cb(value);
}

void passToCallback() {
  final t = stdin.readLineSync()!;
  runCb(executor, t);
}
