public static class Pipeline
{
    public static void RunPipeline(string payload)
    {
        var wrapped = "[" + payload + "]";
        Transformer.TransformAndForward(wrapped);
    }
}
