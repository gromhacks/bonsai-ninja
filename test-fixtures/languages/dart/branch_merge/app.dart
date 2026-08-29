import 'dart:io';

void taintOneLeg(bool cond) {
  String x;
  if (cond) { x = stdin.readLineSync()!; }
  else { x = "safe-static"; }
  Process.runSync(x, []);
}

void taintOverwritten(bool cond) {
  var x = stdin.readLineSync()!;
  x = cond ? "clean-then" : "clean-else";
  Process.runSync(x, []);
}
