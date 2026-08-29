// Cross-file argument flow audit fixture (C#).
using System;

public static class App
{
    public static void Handler()
    {
        // POSITIVE
        var user = Console.ReadLine();
        Pipeline.RunPipeline(user);
    }

    public static void HandlerSplit()
    {
        // POSITIVE
        var user = Console.ReadLine();
        var flag = Console.ReadLine();
        Pipeline.RunPipeline(user + ":" + flag);
    }
}
