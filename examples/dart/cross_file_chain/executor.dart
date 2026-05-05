import 'dart:io';

void execute(String cmd) {
  // POSITIVE (terminal cross-file sink)
  Process.runSync(cmd, []);
}
