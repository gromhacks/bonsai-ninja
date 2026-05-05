import 'transformer.dart';

void runPipeline(String payload) {
  final wrapped = "[$payload]";
  transformAndForward(wrapped);
}
