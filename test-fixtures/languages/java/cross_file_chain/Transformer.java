public class Transformer {
    public static void transformAndForward(String value) throws Exception {
        String upper = value.toUpperCase();
        Executor.execute(upper);
    }
}
