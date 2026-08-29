public static class Transformer
{
    public static void TransformAndForward(string value)
    {
        var upper = value.ToUpper();
        Executor.Execute(upper);
    }
}
