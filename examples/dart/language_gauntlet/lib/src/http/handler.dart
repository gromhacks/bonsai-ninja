// Production Shelf handler. Keeping the remote boundary under lib/ makes the
// gauntlet representative of deployable server code under the default review
// profile; bin/ contains only the local launcher.
import 'package:shelf/shelf.dart';

import '../domain/envelope.dart';
import '../routing/command_router.dart';

Future<String> handle_request(Request request) async {
  // SOURCE — Shelf exposes the remote HTTP request body as a string.
  final raw = await request.readAsString();
  const user = 'remote';

  final envelope = Envelope(
    kind: Kind.run,
    cmd: '$raw',
    user: user,
    length: raw.length,
    extras: [raw],
  )..extras.add(raw.trim());

  return startPipeline(envelope);
}
