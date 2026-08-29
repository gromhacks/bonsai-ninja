package pipeline

import (
	"context"
	"strings"

	domainmodel "example.com/bonsai/language-gauntlet/internal/domain"
	store "example.com/bonsai/language-gauntlet/internal/storage"
)

func makeJoiner(sep string) func(acc, token string) string {
	return func(acc, token string) string {
		if acc == "" {
			return token
		}
		return acc + sep + token
	}
}

func collectExtras(values ...string) []string {
	return values
}

func tokenize(ctx context.Context, cmd string) <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)
		for _, part := range strings.Fields(cmd) {
			select {
			case <-ctx.Done():
				return
			case out <- part:
			}
		}
	}()
	return out
}

func route(env domainmodel.Envelope, joined string) string {
	var boxed any = env.Kind
	switch k := boxed.(type) {
	case domainmodel.Kind:
		env.Kind = k
	default:
		env.Kind = domainmodel.KindRun
	}

	switch env.Kind {
	case domainmodel.KindRun:
		return joined
	case domainmodel.KindEval:
		return strings.TrimSpace(joined)
	default:
		return joined
	}
}

func Orchestrate(ctx context.Context, envelope domainmodel.Envelope) int {
	cmd := envelope.Command()
	envelope.Extras = collectExtras(envelope.Extras...)

	var tokens []string
	for token := range tokenize(ctx, cmd) {
		tokens = append(tokens, strings.TrimSpace(token))
	}

	joiner := makeJoiner(" ")
	joined := ""
	for _, token := range tokens {
		if token == "" {
			continue
		}
		joined = joiner(joined, token)
	}
	routed := route(envelope, joined)

	var valid domainmodel.Envelope
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				valid = domainmodel.NewEnvelope(routed, envelope.User)
			}
		}()
		if routed == "" {
			panic("empty")
		}
		valid = domainmodel.NewEnvelope(routed, envelope.User)
	}()

	return store.Persist(valid)
}
