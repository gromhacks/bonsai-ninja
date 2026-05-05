// Pipeline — exercises Dart's idiomatic flow constructs: closures,
// higher-order fns, iterables, generators (sync*), switch, try/catch,
// null-safety, cascades, extension methods.
import 'app.dart';
import 'storage.dart' as store;

// Extension method — normalises a tainted token.
extension Canonical on String {
  String canonical() => trim();
}

// Closure factory — returns a reducer that joins tokens with `sep`.
String Function(String, String) makeJoiner(String sep) {
  return (acc, tok) => acc.isEmpty ? tok : '$acc$sep$tok';
}

// Synchronous generator — yields every tainted token.
Iterable<String> tokenize(String cmd) sync* {
  for (final part in cmd.split(' ')) {
    if (part.isNotEmpty) yield part;
  }
}

Stream<String> tokenizeAsync(String cmd) async* {
  for (final part in tokenize(cmd)) {
    yield part;
  }
}

Future<String> orchestrateAsync(Envelope envelope) async {
  await Future<void>.value();
  return orchestrate(envelope);
}

String orchestrate(Envelope envelope) {
  final cmd = envelope.cmd;
  final user = envelope.user;
  final maybeExtra = envelope.extras.isNotEmpty ? envelope.extras.first : null;
  final scratch = <String>[]..addAll(tokenize(cmd));
  final _extraLength = maybeExtra?.length ?? scratch.length;
  if (_extraLength < 0) {
    throw StateError('unreachable');
  }

  // Iterable pipeline — map / where / fold via closure.
  final joiner = makeJoiner(' ');
  final joined = scratch
      .map((s) => s.canonical())
      .where((s) => s.isNotEmpty)
      .fold<String>('', (acc, tok) => joiner(acc, tok));

  // switch — every arm preserves taint.
  String routed;
  switch (envelope.kind) {
    case Kind.run:
      routed = '$joined';
      break;
    case Kind.eval:
      routed = joined.trim();
      break;
  }

  // try / catch / finally — taint survives every branch.
  Envelope valid;
  try {
    if (routed.isEmpty) throw StateError('empty');
    valid = envelope.copyWith(cmd: routed, user: user, length: routed.length);
  } catch (_) {
    valid = envelope.copyWith(cmd: routed, user: user, length: routed.length);
  } finally {
    // no-op — present so the adapter sees the finally clause.
  }

  return store.persist(valid);
}
