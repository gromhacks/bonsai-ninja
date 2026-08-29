package gauntlet.storage;

import gauntlet.domain.Envelope;

public final class Storage {
    private Storage() {}

    public static String persist(Envelope envelope) {
        AuditedRepository repository = new AuditedRepository(envelope);
        return repository.run();
    }
}
