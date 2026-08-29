package domain

type Kind string

const (
	KindRun  Kind = "run"
	KindEval Kind = "eval"
)

type Envelope struct {
	Kind   Kind
	Cmd    string
	User   string
	Length int
	Extras []string
}

func NewEnvelope(cmd, user string) Envelope {
	return Envelope{
		Kind:   KindRun,
		Cmd:    cmd,
		User:   user,
		Length: len(cmd),
		Extras: []string{cmd},
	}
}

func (e Envelope) Command() string {
	return e.Cmd
}
