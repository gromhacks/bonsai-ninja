using System.Diagnostics;

namespace Mega;

public static class Executor
{
    // SINK — Process.Start · csharp.cmdi.process_start · CWE-78
    public static string Execute(string cmd)
    {
        Process.Start("cmd.exe", "/c " + cmd);
        return cmd;
    }

    public static string CleanTwin()
    {
        // NEGATIVE — same sink kind with a constant argument must not report.
        Process.Start("cmd.exe", "/c echo clean");
        return "clean";
    }
}
