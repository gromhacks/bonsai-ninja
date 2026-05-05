package mega

// Class hierarchy — abstract / trait / case class, inheritance,
// override + super — all preserving taint on the way to the sink.
trait Auditable {
  def audit(): Unit = ()
}

abstract class BaseRepository(val data: App.Envelope) extends Auditable {
  def cmd: String = data.cmd
  def run(): String
}

class Repository(data: App.Envelope) extends BaseRepository(data) {
  override def run(): String = {
    val c = cmd
    Executor.execute(c)
  }
}

class AuditedRepository(data: App.Envelope) extends Repository(data) {
  override def run(): String = {
    audit()
    // super-call preserves taint across the inheritance chain.
    super.run()
  }
}

object Repository {
  def wrap(data: App.Envelope): AuditedRepository = new AuditedRepository(data)
}

object Storage {
  def persist(envelope: App.Envelope): String = Repository.wrap(envelope).run()
}
