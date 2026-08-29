// Assignment-chain audit fixture (Dart).
// Uses stdin.readLineSync() as source (dart.cli.stdin_readline_sync) +
// Process.run as cmdi sink. The Map<String,String> subscript-read
// shape is a separate adapter audit (Task #265 / receiver-type).
import 'dart:io';
import 'executor.dart';

const String CONST_OK = "ls /tmp";

String passthrough(String x) => x;
String wrap(String x) => "wrapped:$x";
String combine(String acc, String item) => "$acc:$item";

class Bag {
  String payload = "";
}

void chainSimple() {
  // POSITIVE
  final tmp = stdin.readLineSync()!;
  Process.runSync(tmp, []);
}

void chainMultiHop() {
  // POSITIVE
  final t1 = stdin.readLineSync()!;
  final t2 = passthrough(t1);
  final t3 = wrap(t2);
  final t4 = passthrough(t3);
  Process.runSync(t4, []);
}

void chainBranchJoin(bool cond) {
  // POSITIVE
  String t;
  if (cond) {
    t = stdin.readLineSync()!;
  } else {
    t = "safe-static";
  }
  Process.runSync(t, []);
}

void chainLoopCarried(List<String> items) {
  // POSITIVE
  var acc = stdin.readLineSync()!;
  for (final item in items) {
    acc = combine(acc, item);
  }
  Process.runSync(acc, []);
}

void chainFieldWrite() {
  // POSITIVE
  final bag = Bag();
  bag.payload = stdin.readLineSync()!;
  Process.runSync(bag.payload, []);
}

void chainSubscriptWrite() {
  // POSITIVE
  final cmds = <String, String>{};
  cmds["x"] = stdin.readLineSync()!;
  Process.runSync(cmds["x"]!, []);
}

void chainCleanConstant() {
  // NEGATIVE
  final _unused = stdin.readLineSync();
  Process.runSync(CONST_OK, []);
}

void chainCrossFile() {
  // POSITIVE
  final t = stdin.readLineSync()!;
  runInOtherFile(t);
}
