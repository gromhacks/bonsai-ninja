public class Pipeline {
    public static void runPipeline(String payload) throws Exception {
        String wrapped = "[" + payload + "]";
        Transformer.transformAndForward(wrapped);
    }
}
