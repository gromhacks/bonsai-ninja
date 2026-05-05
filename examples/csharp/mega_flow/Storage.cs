namespace Mega;

// Class hierarchy — abstract base, inheritance, virtual + override,
// auto-properties, static factory — all preserving taint on the way
// to the sink.
public abstract class BaseRepository
{
    public Envelope Data { get; }

    protected BaseRepository(Envelope data)
    {
        Data = data;
    }

    // Expression-bodied property exposes the tainted cmd field.
    public string Cmd => Data.Cmd;

    public abstract string Run();
}

public class Repository : BaseRepository
{
    public Repository(Envelope data) : base(data) { }

    public static Repository Wrap(Envelope data) => new Repository(data);

    public override string Run()
    {
        var c = Cmd;
        return Executor.Execute(c);
    }
}

public class AuditedRepository : Repository
{
    public AuditedRepository(Envelope data) : base(data) { }

    public override string Run()
    {
        // base-call preserves taint across the inheritance chain.
        return base.Run();
    }
}

public static class Storage
{
    public static string Persist(Envelope envelope)
    {
        var repo = new AuditedRepository(envelope);
        return repo.Run();
    }
}
