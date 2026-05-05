using System.Diagnostics;

public static class Executor
{
    public static void Execute(string cmd)
    {
        // POSITIVE (terminal cross-file sink)
        Process.Start("sh", "-c " + cmd);
    }
}
