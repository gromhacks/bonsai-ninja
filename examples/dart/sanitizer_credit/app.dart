import 'dart:io';
import 'package:html_unescape/html_unescape.dart';

void unsanitized() {
  final t = stdin.readLineSync()!;
  Process.runSync(t, []);
}

void sanitized() {
  final t = stdin.readLineSync()!;
  // Safe argv form: static executable, attacker data is an argument,
  // and runInShell is explicitly false.
  Process.runSync('echo', [t], runInShell: false);
}
