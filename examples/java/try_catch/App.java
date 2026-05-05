public class App {
    public void taintedThroughTry() throws Exception {
        String t = "";
        try {
            t = System.getenv("CMD");
        } catch (Exception e) {
            t = "";
        }
        Runtime.getRuntime().exec(t);
    }
}
