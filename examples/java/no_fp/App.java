public class App {
    static final String CONST_OK = "ls /tmp";
    public void decoy() throws Exception {
        String unused = System.getenv("IGNORED");
        Runtime.getRuntime().exec(CONST_OK);
    }
    public String unrelatedChain() {
        String a = "hello";
        return a.toUpperCase();
    }
}
