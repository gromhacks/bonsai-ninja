// Class hierarchy — inheritance (extends / super), getters/setters,
// static methods — all preserving taint on the way to the sink.
const { execute } = require("./executor");

class Repository {
  constructor(data) {
    this._data = data;
  }

  // Getter propagates taint out of the private field.
  get cmd() {
    return this._data.cmd;
  }

  set cmd(v) {
    this._data = { ...this._data, cmd: v };
  }

  static wrap(data) {
    return new Repository(data);
  }

  run() {
    const c = this.cmd;
    return execute(c);
  }
}

class AuditedRepository extends Repository {
  constructor(data) {
    super(data);
  }

  run() {
    // super-call preserves taint through the inheritance chain.
    return super.run();
  }
}

async function persist(data) {
  const repo = new AuditedRepository(data);
  return repo.run();
}

module.exports = { persist, Repository, AuditedRepository };
