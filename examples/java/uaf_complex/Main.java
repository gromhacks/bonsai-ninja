import java.io.InputStream;
import java.util.concurrent.Future;
import java.util.concurrent.locks.ReentrantLock;

public class Main {

    // Use after close — direct pair. Binding `in` matches the rule's
    // `requires_state.name`.
    void use_after_close(InputStream in) throws Exception {
        in.close();
        in.read();
    }

    // Use after close in a finally block.
    void close_in_finally(InputStream in) throws Exception {
        try {
            in.read();
        } finally {
            in.close();
        }
        in.read();
    }

    // Future cancel followed by `get` — binding `f`.
    void future_cancel_then_get(Future<String> f) throws Exception {
        f.cancel(true);
        f.get();
    }

    // Conditional close — read still reachable on the close path.
    int conditional_close(InputStream in, boolean done) throws Exception {
        if (done) {
            in.close();
        }
        return in.read();
    }

    // ReentrantLock unlock-then-use.
    void unlock_then_use(ReentrantLock m) {
        m.unlock();
        m.lock();
    }

    public static void main(String[] args) {}
}
