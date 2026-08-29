package gauntlet.storage;

import gauntlet.domain.Envelope;
import gauntlet.runtime.Executor;

public class Repository extends BaseRepository<Envelope> {
    public Repository(Envelope data) {
        super(data);
    }

    @Override
    public String run() {
        String value = cmd();
        return Executor.execute(value);
    }
}
