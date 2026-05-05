package mega

typealias RepoEnvelope = App.Envelope

// Class hierarchy — open/abstract/override, properties with custom
// getters, sealed classes, companion-object factory — all preserving
// taint on the way to the sink.
sealed class RepoState {
    data object Active : RepoState()
}

abstract class BaseRepository(val data: RepoEnvelope) {
    private val state: RepoState = RepoState.Active

    // Custom getter exposes the tainted cmd field.
    open val cmd: String get() = data.cmd

    abstract fun run(): String
}

open class Repository(data: RepoEnvelope) : BaseRepository(data) {
    companion object {
        fun wrap(data: RepoEnvelope): Repository = Repository(data)
    }

    override fun run(): String {
        val c = cmd
        return Executor.execute(c)
    }
}

class AuditedRepository(data: RepoEnvelope) : Repository(data) {
    override fun run(): String {
        // super-call preserves taint across the inheritance chain.
        return super.run()
    }
}

object Storage {
    fun persist(envelope: RepoEnvelope): String {
        val repo = AuditedRepository(envelope)
        return repo.run()
    }
}
