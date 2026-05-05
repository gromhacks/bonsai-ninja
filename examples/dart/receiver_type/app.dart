// Receiver-type audit fixture (Dart).
// Process.runSync — class-name receiver, no instance resolution
// required.
import 'dart:io';

void handle() {
  // POSITIVE
  final tainted = stdin.readLineSync()!;
  Process.runSync(tainted, []);
}
