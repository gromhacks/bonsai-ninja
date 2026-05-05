package main

// Interface + struct embedding — Go's idiomatic composition. Taint
// rides through embedded-struct method promotion into the sink.

// Runner — interface implemented by every Repository variant.
type Runner interface {
	Run() int
}

type Repository struct {
	data Envelope
}

func (r *Repository) Cmd() string {
	return r.data.Cmd
}

func (r *Repository) Run() int {
	c := r.Cmd()
	return Execute(c)
}

// AuditedRepository embeds Repository — method promotion exposes Run.
type AuditedRepository struct {
	*Repository
}

func (a *AuditedRepository) Run() int {
	// Embedded-struct promotion preserves taint across the chain.
	return a.Repository.Run()
}

// Persist wraps the tainted payload in a Repository and dispatches
// via the Runner interface.
func Persist(data Envelope) int {
	var repo Runner = &AuditedRepository{Repository: &Repository{data: data}}
	return repo.Run()
}
