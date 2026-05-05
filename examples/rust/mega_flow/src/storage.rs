use crate::executor;
use crate::Envelope;

// Trait + impl + generics — Rust's idiomatic composition. Taint rides
// through trait dispatch into the sink.

pub trait Runnable {
    fn run(&self) -> String;
}

pub struct Repository {
    data: Envelope,
}

impl Repository {
    pub fn new(data: Envelope) -> Self {
        Self { data }
    }

    fn cmd(&self) -> &str {
        &self.data.cmd
    }
}

impl Runnable for Repository {
    fn run(&self) -> String {
        let c = self.cmd();
        executor::execute(c)
    }
}

// New-type wrapper delegating via trait — preserves taint.
pub struct AuditedRepository(Repository);

impl AuditedRepository {
    pub fn wrap(data: Envelope) -> Self {
        Self(Repository::new(data))
    }
}

impl Runnable for AuditedRepository {
    fn run(&self) -> String {
        // Delegate preserves taint across the trait chain.
        self.0.run()
    }
}

pub fn persist(envelope: Envelope) -> String {
    let repo = AuditedRepository::wrap(envelope);
    repo.run()
}
