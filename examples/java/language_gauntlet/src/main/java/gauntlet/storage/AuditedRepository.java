package gauntlet.storage;

import gauntlet.domain.Envelope;

public final class AuditedRepository extends Repository {
    public AuditedRepository(Envelope data) {
        super(data);
    }

    @Override
    public String run() {
        return super.run();
    }
}
