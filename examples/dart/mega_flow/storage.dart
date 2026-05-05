// Class hierarchy — abstract base, mixins, inheritance, factory
// constructors — all preserving taint on the way to the sink.
import 'app.dart';
import 'executor.dart';

mixin Auditable {
  void audit() {}
}

abstract class BaseRepository {
  final Envelope data;
  BaseRepository(this.data);

  // Getter exposes the tainted cmd field.
  String get cmd => data.cmd;

  String run();
}

class Repository extends BaseRepository with Auditable {
  Repository(super.data);

  factory Repository.wrap(Envelope data) => Repository(data);

  @override
  String run() {
    final c = cmd;
    return execute(c);
  }
}

class AuditedRepository extends Repository {
  AuditedRepository(super.data);

  @override
  String run() {
    audit();
    // super-call preserves taint across the inheritance chain.
    return super.run();
  }
}

String persist(Envelope envelope) {
  final repo = AuditedRepository(envelope);
  return repo.run();
}
