import 'dart:io';

void taintedThroughTry() {
  String t;
  try {
    t = stdin.readLineSync()!;
  } catch (_) {
    t = "";
  }
  Process.runSync(t, []);
}
