using System;
using System.Diagnostics;
using System.Web;

public static class App
{
    public static void Unsanitized()
    {
        var t = Console.ReadLine();
        Process.Start("sh", "-c " + t);
    }

    public static void Sanitized()
    {
        var t = Console.ReadLine();
        var safe = HttpUtility.HtmlEncode(t);
        Process.Start("sh", "-c " + safe);
    }

    public static void EncodedXss()
    {
        var t = Console.ReadLine();
        var safe = HttpUtility.HtmlEncode(t);
        Response.Write(safe);
    }
}
