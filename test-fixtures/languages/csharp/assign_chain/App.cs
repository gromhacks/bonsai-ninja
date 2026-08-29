// Assignment-chain audit fixture (C#).
// Uses Console.ReadLine as the source (csharp.source.console_readline)
// because the C# adapter doesn't yet surface HttpRequest property
// reads — see Task #265 for that gap.
using System;
using System.Collections.Generic;
using System.Diagnostics;

public static class App
{
    const string CONST_OK = "ls /tmp";

    static string Passthrough(string x) => x;
    static string Wrap(string x) => "wrapped:" + x;
    static string Combine(string acc, string item) => acc + ":" + item;

    class Bag { public string Payload = ""; }

    public static void ChainSimple()
    {
        // POSITIVE
        var tmp = Console.ReadLine();
        Process.Start("sh", "-c " + tmp);
    }

    public static void ChainMultiHop()
    {
        // POSITIVE
        var t1 = Console.ReadLine();
        var t2 = Passthrough(t1);
        var t3 = Wrap(t2);
        var t4 = Passthrough(t3);
        Process.Start("sh", "-c " + t4);
    }

    public static void ChainBranchJoin(bool cond)
    {
        // POSITIVE
        string t;
        if (cond) { t = Console.ReadLine(); }
        else { t = "safe-static"; }
        Process.Start("sh", "-c " + t);
    }

    public static void ChainLoopCarried(IEnumerable<string> items)
    {
        // POSITIVE
        var acc = Console.ReadLine();
        foreach (var item in items) { acc = Combine(acc, item); }
        Process.Start("sh", "-c " + acc);
    }

    public static void ChainFieldWrite()
    {
        // POSITIVE
        var bag = new Bag();
        bag.Payload = Console.ReadLine();
        Process.Start("sh", "-c " + bag.Payload);
    }

    public static void ChainSubscriptWrite()
    {
        // POSITIVE
        var cmds = new Dictionary<string, string>();
        cmds["x"] = Console.ReadLine();
        Process.Start("sh", "-c " + cmds["x"]);
    }

    public static void ChainCleanConstant()
    {
        // NEGATIVE
        var _unused = Console.ReadLine();
        Process.Start("sh", "-c " + CONST_OK);
    }

    public static void ChainCrossFile()
    {
        // POSITIVE
        var t = Console.ReadLine();
        Executor.RunInOtherFile(t);
    }
}
