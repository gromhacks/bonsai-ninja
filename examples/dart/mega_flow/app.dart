// mega_flow Dart entry — reads stdin, then dispatches through a
// pipeline that exercises every idiomatic Dart flow construct
// (null-safety, async/await, streams, generators, switch, classes +
// mixins, named/optional params, cascades).
import 'dart:io';
import 'pipeline.dart';

enum Kind { run, eval }

class Envelope {
  final Kind kind;
  final String cmd;
  final String user;
  final int length;
  final List<String> extras;

  Envelope({
    required this.kind,
    required this.cmd,
    required this.user,
    required this.length,
    required this.extras,
  });

  Envelope copyWith({Kind? kind, String? cmd, String? user, int? length, List<String>? extras}) =>
      Envelope(
        kind: kind ?? this.kind,
        cmd: cmd ?? this.cmd,
        user: user ?? this.user,
        length: length ?? this.length,
        extras: extras ?? this.extras,
      );
}

Future<String> handle_request() async {
  // SOURCE — stdin.readLineSync() reads one tainted line from stdin.
  final raw = stdin.readLineSync() ?? '';
  final user = Platform.environment['USER'] ?? 'anon';

  final envelope = Envelope(
    kind: Kind.run,
    cmd: '$raw',
    user: user,
    length: raw.length,
    extras: [raw],
  )..extras.add(raw?.trim() ?? '');

  return await orchestrateAsync(envelope);
}

Future<void> main(List<String> args) async {
  await handle_request();
}
