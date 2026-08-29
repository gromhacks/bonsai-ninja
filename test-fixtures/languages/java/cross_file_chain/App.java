// Cross-file argument flow audit fixture (Java).
public class App {
    public void handler() throws Exception {
        // POSITIVE
        String user = System.getenv("CMD");
        Pipeline.runPipeline(user);
    }

    public void handlerSplit() throws Exception {
        // POSITIVE
        String user = System.getenv("FROM");
        String flag = System.getenv("FLAG");
        Pipeline.runPipeline(user + ":" + flag);
    }
}
