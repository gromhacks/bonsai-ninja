using System;
using System.Diagnostics;

public static class App
{
    const string CONST_OK = "ls /tmp";
    public static void Decoy()
    {
        var unused = Console.ReadLine();
        Process.Start("sh", "-c " + CONST_OK);
    }
    public static string UnrelatedChain()
    {
        var a = "hello";
        return a.ToUpper();
    }
}
