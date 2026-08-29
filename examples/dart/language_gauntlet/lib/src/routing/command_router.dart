import '../domain/envelope.dart';
import '../pipeline/pipeline.dart';

typedef RouteCallback = String Function(Envelope envelope);

String startPipeline(Envelope initial) => orchestrate(initial);

Envelope routeEnvelope(Envelope initial) => CommandRouter(initial).route();

/// Nested-library bridge deliberately kept on the critical dataflow path.
class CommandRouter {
  Envelope current;

  CommandRouter(this.current);

  Envelope snapshot() => current.copyWith(cmd: current.cmd);

  Envelope route() {
    var routed = snapshot();
    for (var attempt = 0; attempt < 2; attempt++) {
      if (attempt == 0) {
        routed = routed.copyWith(cmd: routed.cmd);
      } else {
        current = routed;
        routed = current;
      }
    }
    return routed;
  }

  String dispatch(RouteCallback next) => next(route());

  // Future-based syntax exercises Dart's async callable lowering while the
  // deterministic command-line gauntlet uses dispatch directly.
  Future<String> dispatchAsync(RouteCallback next) async {
    await Future<void>.value();
    return dispatch(next);
  }
}
