namespace Mega;

using System.Collections.Generic;
using System.Threading.Tasks;

// mega_flow C# entry — reads a stdin line, then dispatches through a
// pipeline that exercises every idiomatic C# flow construct (records,
// pattern matching, LINQ, async/await, nullable refs, tuples, switch
// expressions).
public enum Kind { Run, Eval }

public record Envelope(Kind Kind, string Cmd, string User, int Length, List<string> Extras);

public class App
{
    public string Handle()
    {
        // SOURCE — Console.ReadLine() reads one tainted stdin line.
        // Matched by csharp.source.console_readline (call-kind, name=ReadLine).
        var raw = System.Console.ReadLine();
        var user = System.Environment.GetEnvironmentVariable("USER") ?? "anon";

        var envelope = new Envelope(
            Kind: Kind.Run,
            Cmd: $"{raw}",
            User: user,
            Length: raw?.Length ?? 0,
            Extras: new List<string> { raw! });

        return Pipeline.OrchestrateAsync(envelope).GetAwaiter().GetResult();
    }
}
