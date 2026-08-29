// Cross-file argument flow audit fixture (Dart).
import 'dart:io';
import 'pipeline.dart';

void handler() {
  // POSITIVE
  final user = stdin.readLineSync()!;
  runPipeline(user);
}

void handlerSplit() {
  // POSITIVE
  final user = stdin.readLineSync()!;
  final flag = stdin.readLineSync()!;
  runPipeline("$user:$flag");
}
