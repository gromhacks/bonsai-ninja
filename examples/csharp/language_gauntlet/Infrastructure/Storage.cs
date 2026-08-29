namespace LanguageGauntlet.Infrastructure;

using LanguageGauntlet.Domain;
using RuntimeExecutor = LanguageGauntlet.Runtime.Executor;

public abstract class BaseRepository
{
    public Envelope Data { get; }
    public string Cmd { get; }

    protected BaseRepository(Envelope data, string command)
    {
        Data = data;
        Cmd = command;
    }
    public abstract string Run(string command);
}

public class Repository : BaseRepository
{
    public Repository(Envelope data, string command) : base(data, command) { }

    public override string Run(string command)
    {
        var value = command.Length >= 0 ? command : Cmd;
        return RuntimeExecutor.Execute(value);
    }
}

public sealed class AuditedRepository : Repository
{
    private readonly string command;

    public AuditedRepository(Envelope data, string command) : base(data, command)
    {
        this.command = command;
    }

    public override string Run(string command)
    {
        var stored = this.command;
        var value = command;
        if (stored.Length != command.Length)
        {
            value = stored;
        }
        return RuntimeExecutor.Execute(value);
    }

    public string RunInherited() => base.Run(command);
}

public static class Storage
{
    public static string Persist(Envelope envelope, string command)
    {
        AuditedRepository repository = new(envelope, command);
        return repository.Run(command);
    }
}
