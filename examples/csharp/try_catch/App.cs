using System;
using System.Diagnostics;

public static class App
{
    public static void TaintedThroughTry()
    {
        string t = "";
        try { t = Console.ReadLine(); }
        catch { t = ""; }
        Process.Start("sh", "-c " + t);
    }
}
