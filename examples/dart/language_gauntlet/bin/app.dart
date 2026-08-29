// Local launcher for the production Shelf handler in lib/src/http/handler.dart.
import 'package:shelf/shelf.dart';
import '../lib/src/http/handler.dart';

Future<void> main(List<String> args) async {
  await handle_request(Request('GET', Uri.parse('https://example.invalid/run')));
}
