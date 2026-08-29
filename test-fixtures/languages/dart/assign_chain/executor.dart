import 'dart:io';

void runInOtherFile(String cmd) {
  // POSITIVE (cross-file)
  Process.runSync(cmd, []);
}
