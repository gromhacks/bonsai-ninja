package mega;

// Class hierarchy — abstract base, inheritance, generics, method
// override + super — all preserving taint on the way to the sink.
public class Storage {
    static String persist(App.Envelope envelope) {
        return new AuditedRepository(envelope).run();
    }

    static abstract class BaseRepository<T extends App.Envelope> {
        protected final T data;

        BaseRepository(T data) { this.data = data; }

        // Accessor propagates taint out of the field.
        String cmd() { return data.cmd(); }

        abstract String run();
    }

    static class Repository extends BaseRepository<App.Envelope> {
        Repository(App.Envelope data) { super(data); }

        @Override
        String run() {
            String c = cmd();
            return Executor.execute(c);
        }
    }

    static class AuditedRepository extends Repository {
        AuditedRepository(App.Envelope data) { super(data); }

        @Override
        String run() {
            // super-call preserves taint across the inheritance chain.
            return super.run();
        }
    }
}
