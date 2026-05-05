// Class hierarchy — generics, inheritance (extends / super),
// getters/setters, abstract classes, access modifiers — all
// preserving taint on the way to the sink.
import { execute } from "./executor";

abstract class BaseRepository<T extends { cmd: string }> {
  protected _data: T;

  constructor(data: T) {
    this._data = data;
  }

  get cmd(): string {
    return this._data.cmd;
  }

  set cmd(v: string) {
    this._data = { ...this._data, cmd: v };
  }

  abstract run(): unknown;
}

class Repository<T extends { cmd: string }> extends BaseRepository<T> {
  static wrap<U extends { cmd: string }>(data: U): Repository<U> {
    return new Repository<U>(data);
  }

  run(): unknown {
    const c: string = this.cmd;
    return execute(c);
  }
}

class AuditedRepository<T extends { cmd: string }> extends Repository<T> {
  run(): unknown {
    // super-call preserves taint across the inheritance chain.
    return super.run();
  }
}

export async function persist<T extends { cmd: string }>(data: T): Promise<unknown> {
  const repo: AuditedRepository<T> = new AuditedRepository<T>(data);
  return repo.run();
}

export { Repository, AuditedRepository, BaseRepository };
