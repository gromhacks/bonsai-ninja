using System;
using System.Diagnostics;

public static class App
{
    public static void Executor(string cmd)
    {
        Process.Start("sh", "-c " + cmd);
    }

    public static void RunCb(Action<string> cb, string value)
    {
        cb(value);
    }

    public static void PassToCallback()
    {
        var t = Console.ReadLine();
        RunCb(Executor, t);
    }
}
