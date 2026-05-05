<?php
// Class hierarchy — inheritance, abstract, interfaces, constructor
// promotion, readonly, getters, static factory — all preserving
// taint on the way to the sink.
require_once __DIR__ . '/executor.php';

interface Runnable {
    public function run(): string;
}

abstract class BaseRepository implements Runnable {
    public function __construct(protected array $data) {}

    // Getter propagates taint out of the instance array.
    public function cmd(): string {
        return $this->data['cmd'];
    }

    abstract public function run(): string;
}

class Repository extends BaseRepository {
    public static function wrap(array $data): static {
        return new static($data);
    }

    public function run(): string {
        return Executor::execute($this->cmd());
    }
}

class AuditedRepository extends Repository {
    public function run(): string {
        // parent-call preserves taint across the inheritance chain.
        return parent::run();
    }
}

class Storage {
    public static function persist(array $envelope): string {
        return AuditedRepository::wrap($envelope)->run();
    }
}
