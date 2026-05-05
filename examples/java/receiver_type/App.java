// Receiver-type audit fixture (Java).
//
// Three POSITIVE shapes:
//
//   1. Class-name chained call `Runtime.getRuntime().exec(tainted)`.
//      Worked before — the chain literal contains `Runtime.getRuntime`
//      so the rule sees the type.
//
//   2. JDBC factory chain `c.createStatement(); st.execute(tainted)`.
//      The factory-method-name inference (kit.rs
//      `infer_type_from_factory_method`) binds `st` to type
//      `Statement` because `createStatement` matches the
//      `<verb><PascalTail>` pattern.
//
//   3. SLF4J `Logger log = LoggerFactory.getLogger(...)` followed by
//      `log.info("user " + tainted)`. The verb-prefix heuristic binds
//      `log` to `Logger` (not `LoggerFactory`) because the factory
//      method name `getLogger` carries the return type.
//
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {
    public void handle() throws Exception {
        // POSITIVE 1: class-receiver chained call.
        String tainted = System.getenv("CMD");
        Runtime.getRuntime().exec(tainted);
    }

    public void handleSql() throws Exception {
        // POSITIVE 2: JDBC factory-chained statement.
        String taintedSql = System.getenv("Q");
        Connection c = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement st = c.createStatement();
        st.execute(taintedSql);
    }

    public void handleLog() throws Exception {
        // POSITIVE 3: SLF4J factory-chained logger.
        String taintedLog = System.getenv("USER");
        Logger log = LoggerFactory.getLogger(App.class);
        log.info("user " + taintedLog);
    }
}
