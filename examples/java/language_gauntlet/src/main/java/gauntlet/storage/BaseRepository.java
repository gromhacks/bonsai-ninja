package gauntlet.storage;

import gauntlet.domain.Envelope;

public abstract class BaseRepository<T extends Envelope> {
    protected final T data;

    protected BaseRepository(T data) {
        this.data = data;
    }

    protected String cmd() {
        return data.cmd();
    }

    public abstract String run();
}
