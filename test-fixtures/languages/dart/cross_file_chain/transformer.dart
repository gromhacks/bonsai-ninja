import 'executor.dart';

void transformAndForward(String value) {
  final upper = value.toUpperCase();
  execute(upper);
}
