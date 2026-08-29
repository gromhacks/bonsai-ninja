using System.Diagnostics;

public static class Executor
{
    public static void RunInOtherFile(string cmd)
    {
        // POSITIVE (cross-file)
        Process.Start("sh", "-c " + cmd);
    }
}
