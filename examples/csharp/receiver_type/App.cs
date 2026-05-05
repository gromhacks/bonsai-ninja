// Receiver-type audit fixture (C#).
// Process.Start — class-name receiver. Instance-receiver shapes
// (`client.GetStringAsync` where client: HttpClient) are a deeper
// adapter gap captured separately as Task #283.
using System;
using System.Diagnostics;

public static class App
{
    public static void Handle()
    {
        // POSITIVE
        var tainted = Console.ReadLine();
        Process.Start("sh", "-c " + tainted);
    }
}
