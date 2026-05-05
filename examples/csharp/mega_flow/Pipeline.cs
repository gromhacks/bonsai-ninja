using System;
using System.Collections.Generic;
using System.Linq;
using static System.String;
using Tasks = System.Threading.Tasks;

namespace Mega;

// Pipeline — exercises C#'s idiomatic flow constructs: LINQ, lambdas,
// delegates, async/await, try/catch/finally, switch expressions,
// pattern matching, records, tuples, yield iterators.
public static class Pipeline
{
    public static async Tasks.Task<string> OrchestrateAsync(Envelope envelope)
    {
        await Tasks.Task.Yield();
        return Orchestrate(envelope);
    }

    // Delegate factory — returns a Func reducer that joins tokens.
    private static Func<string, string, string> MakeJoiner(string sep)
        => (acc, tok) => string.IsNullOrEmpty(acc) ? tok : $"{acc}{sep}{tok}";

    // yield iterator — streams every tainted token.
    private static IEnumerable<string> Tokenize(string cmd)
    {
        foreach (var part in cmd.Split(' '))
        {
            if (!string.IsNullOrEmpty(part))
                yield return part;
        }
    }

    public static string Orchestrate(Envelope envelope)
    {
        var cmd = envelope.Cmd;
        var user = envelope.User;
        string? maybeUser = envelope.User;
        if (envelope is { Kind: Kind.Run })
        {
            user = maybeUser ?? user;
        }
        Tuple<string, int> legacyTuple = Tuple.Create(cmd, cmd.Length);
        ValueTuple<string, string> namedTuple = (legacyTuple.Item1, user);
        cmd = namedTuple.Item1;

        // LINQ pipeline: Select → Where → Aggregate with a closure.
        var joiner = MakeJoiner(" ");
        var joined = Tokenize(cmd)
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .Aggregate("", joiner);

        // Switch expression — every arm preserves taint.
        var routed = envelope.Kind switch
        {
            Kind.Run  => $"{joined}",
            Kind.Eval => joined.Trim(),
            _         => joined,
        };

        // try / catch / finally — taint survives every branch.
        Envelope valid;
        using (var audit = new AuditScope())
        {
            try
            {
                if (IsNullOrEmpty(routed)) throw new InvalidOperationException("empty");
                valid = envelope with { Cmd = routed, User = user, Length = routed.Length };
            }
            catch
            {
                valid = envelope with { Cmd = routed, User = user, Length = routed.Length };
            }
            finally
            {
                audit.Dispose();
            }
        }

        return Storage.Persist(valid);
    }

    private sealed class AuditScope : IDisposable
    {
        public void Dispose() { }
    }
}
