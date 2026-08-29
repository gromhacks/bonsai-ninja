namespace LanguageGauntlet.Runtime;

using System.Diagnostics;

public static class Executor
{
    public static string Execute(string cmd)
    {
        // SINK -- Process.Start / CWE-78.
        Process.Start("cmd.exe", "/c " + cmd);
        return cmd;
    }

    public static string CleanTwin()
    {
        // NEGATIVE -- the constant argument must remain untainted.
        Process.Start("cmd.exe", "/c echo clean");
        return "clean";
    }
}
