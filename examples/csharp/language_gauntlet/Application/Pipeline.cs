namespace LanguageGauntlet.Application;

using System;
using System.Collections.Generic;
using System.Linq;
using LanguageGauntlet.Domain;
using Store = LanguageGauntlet.Infrastructure.Storage;
using static System.String;
using Tasks = System.Threading.Tasks;

public static class Pipeline
{
    public static async Tasks.Task<string> OrchestrateAsync(Envelope envelope, string source)
    {
        await Tasks.Task.Yield();
        return Orchestrate(envelope, source);
    }

    private static Func<string, string, string> MakeJoiner(string sep) =>
        (acc, tok) => IsNullOrEmpty(acc) ? tok : $"{acc}{sep}{tok}";

    private static IEnumerable<string> Tokenize(string cmd)
    {
        foreach (var part in cmd.Split(' '))
        {
            if (!IsNullOrEmpty(part))
            {
                yield return part;
            }
        }
    }

    private static string RouteDirect(Kind kind, string source) => kind switch
    {
        Kind.Run => source,
        Kind.Eval => source.Trim(),
        _ => source,
    };

    public static string Orchestrate(Envelope envelope, string source)
    {
        var cmd = source;
        string? maybeUser = envelope.User;
        var user = envelope is { Kind: Kind.Run }
            ? maybeUser ?? envelope.User
            : envelope.User;

        Tuple<string, int> legacyTuple = Tuple.Create(cmd, cmd.Length);
        ValueTuple<string, string> namedTuple = (legacyTuple.Item1, user);
        cmd = namedTuple.Item1;

        var joiner = MakeJoiner(" ");
        var joined = Tokenize(cmd)
            .Select(value => value.Trim())
            .Where(value => value.Length > 0)
            .Aggregate("", joiner);

        var routed = envelope.Kind switch
        {
            Kind.Run => $"{joined}",
            Kind.Eval => joined.Trim(),
            _ => joined,
        };
        var selected = RouteDirect(envelope.Kind, source);

        Envelope valid;
        using (var audit = new AuditScope())
        {
            try
            {
                if (IsNullOrEmpty(routed)) throw new InvalidOperationException("empty");
                valid = envelope with { Cmd = selected, User = user, Length = selected.Length };
            }
            catch
            {
                valid = envelope with { Cmd = selected, User = user, Length = selected.Length };
            }
            finally
            {
                audit.MarkComplete();
            }
        }

        return Store.Persist(valid, selected);
    }

    private sealed class AuditScope : IDisposable
    {
        public void MarkComplete() { }
        public void Dispose() { }
    }
}
