import 'package:shelf/shelf.dart';
Response encoded(Request request) {
  return Response.found(Uri.encodeFull(request.url.queryParameters['next']!));
}
Response direct(Request request) {
  return Response.found(request.url.queryParameters['next']!);
}
