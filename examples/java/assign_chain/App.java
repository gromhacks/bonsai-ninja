// Assignment-chain audit fixture (Java).
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;

public class App {
    static final String CONST_OK = "ls /tmp";

    static String passthrough(String x) { return x; }
    static String wrap(String x) { return "wrapped:" + x; }
    static String combine(String acc, String item) { return acc + ":" + item; }

    static class Bag {
        String payload = "";
    }

    public void chainSimple(HttpServletRequest req) throws IOException {
        // POSITIVE
        String tmp = req.getParameter("c1");
        Runtime.getRuntime().exec(tmp);
    }

    public void chainMultiHop(HttpServletRequest req) throws IOException {
        // POSITIVE
        String t1 = req.getParameter("c2");
        String t2 = passthrough(t1);
        String t3 = wrap(t2);
        String t4 = passthrough(t3);
        Runtime.getRuntime().exec(t4);
    }

    public void chainBranchJoin(HttpServletRequest req, boolean cond) throws IOException {
        // POSITIVE
        String t;
        if (cond) {
            t = req.getParameter("c3");
        } else {
            t = "safe-static";
        }
        Runtime.getRuntime().exec(t);
    }

    public void chainLoopCarried(HttpServletRequest req, String[] items) throws IOException {
        // POSITIVE
        String acc = req.getParameter("c4");
        for (String item : items) {
            acc = combine(acc, item);
        }
        Runtime.getRuntime().exec(acc);
    }

    public void chainFieldWrite(HttpServletRequest req) throws IOException {
        // POSITIVE
        Bag bag = new Bag();
        bag.payload = req.getParameter("c5");
        Runtime.getRuntime().exec(bag.payload);
    }

    public void chainSubscriptWrite(HttpServletRequest req) throws IOException {
        // POSITIVE
        Map<String, String> cmds = new HashMap<>();
        cmds.put("x", req.getParameter("c6"));
        Runtime.getRuntime().exec(cmds.get("x"));
    }

    public void chainCleanConstant(HttpServletRequest req) throws IOException {
        // NEGATIVE
        String unused = req.getParameter("ignored");
        Runtime.getRuntime().exec(CONST_OK);
    }

    public void chainCrossFile(HttpServletRequest req) throws IOException {
        // POSITIVE
        String t = req.getParameter("c9");
        Executor.runInOtherFile(t);
    }
}
