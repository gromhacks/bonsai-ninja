namespace LanguageGauntlet.Domain;

using System.Collections.Generic;

public enum Kind { Run, Eval }

public record Envelope(Kind Kind, string Cmd, string User, int Length, List<string> Extras);

public static class EnvelopeFactory
{
    public static Envelope Create(string cmd, string user) =>
        new(Kind.Run, Cmd: $"{cmd}", User: user, Length: cmd.Length, Extras: new List<string> { cmd });
}
