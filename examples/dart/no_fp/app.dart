import 'dart:io';

const String CONST_OK = "ls /tmp";

void decoy() {
  final _unused = stdin.readLineSync();
  Process.runSync(CONST_OK, []);
}

String unrelatedChain() {
  return "hello".toUpperCase();
}
