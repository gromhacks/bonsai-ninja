public class App {
    public void taintOneLeg(boolean cond) throws Exception {
        String x;
        if (cond) { x = System.getenv("CMD"); }
        else { x = "safe-static"; }
        Runtime.getRuntime().exec(x);
    }

    public void taintOverwritten(boolean cond) throws Exception {
        String x = System.getenv("CMD");
        if (cond) { x = "clean-then"; }
        else { x = "clean-else"; }
        Runtime.getRuntime().exec(x);
    }
}
