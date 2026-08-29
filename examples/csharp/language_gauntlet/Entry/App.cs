namespace LanguageGauntlet.Entry;

using LanguageGauntlet.Application;
using LanguageGauntlet.Domain;
using Microsoft.AspNetCore.Mvc;

public sealed class App
{
    public string Handle([FromQuery] string raw)
    {
        // SOURCE -- ASP.NET binds the remote query parameter.
        const string user = "remote";
        var envelope = EnvelopeFactory.Create(raw, user);
        return Pipeline.OrchestrateAsync(envelope, raw).GetAwaiter().GetResult();
    }
}
