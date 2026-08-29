package storage

import (
	domainmodel "example.com/bonsai/language-gauntlet/internal/domain"
	execflow "example.com/bonsai/language-gauntlet/internal/runtime"
)

type Runner interface {
	Run() int
}

var _ Runner = (*AuditedRepository)(nil)

type Repository struct {
	data domainmodel.Envelope
}

func NewRepository(data domainmodel.Envelope) *Repository {
	return &Repository{data: data}
}

func (repository *Repository) Cmd() string {
	return repository.data.Command()
}

func (repository *Repository) Run() int {
	cmd := repository.Cmd()
	return execflow.Execute(cmd)
}

type AuditedRepository struct {
	*Repository
}

func NewAuditedRepository(data domainmodel.Envelope) *AuditedRepository {
	return &AuditedRepository{Repository: NewRepository(data)}
}

func (repository *AuditedRepository) Run() int {
	return repository.Repository.Run()
}

func Persist(data domainmodel.Envelope) int {
	repository := NewAuditedRepository(data)
	return repository.Run()
}
