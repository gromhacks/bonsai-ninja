using System;
using System.Diagnostics;

public static class App
{
    public static void TaintOneLeg(bool cond)
    {
        string x;
        if (cond) { x = Console.ReadLine(); }
        else { x = "safe-static"; }
        Process.Start("sh", "-c " + x);
    }

    public static void TaintOverwritten(bool cond)
    {
        var x = Console.ReadLine();
        if (cond) { x = "clean-then"; }
        else { x = "clean-else"; }
        Process.Start("sh", "-c " + x);
    }
}
