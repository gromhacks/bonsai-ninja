package main

import (
	"context"
	"strings"
)

// Orchestrate — exercises Go's idiomatic flow constructs: goroutines,
// channels, defer, select, context cancellation, closures, variadic
// functions, range-over-channel, type switch.

// makeJoiner — closure factory returning a reducer that joins tokens.
func makeJoiner(sep string) func(acc, tok string) string {
	return func(acc, tok string) string {
		if acc == "" {
			return tok
		}
		return acc + sep + tok
	}
}

func collectExtras(values ...string) []string {
	return values
}

// tokenize — generator goroutine that streams tainted tokens over a channel.
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

func Orchestrate(ctx context.Context, env Envelope) int {
	cmd := env.Cmd
	user := env.User
	env.Extras = collectExtras(env.Extras...)

	// range-over-channel — consume tainted tokens from the goroutine.
	var tokens []string
	for tok := range tokenize(ctx, cmd) {
		tokens = append(tokens, strings.TrimSpace(tok))
	}

	// Reduce via closure — taint rides the accumulator.
	joiner := makeJoiner(" ")
	joined := ""
	for _, t := range tokens {
		if t == "" {
			continue
		}
		joined = joiner(joined, t)
	}

	// Switch with fall-through — every arm preserves taint.
	var routed string
	var boxedKind any = env.Kind
	switch k := boxedKind.(type) {
	case Kind:
		env.Kind = k
	default:
		env.Kind = KindRun
	}
	switch env.Kind {
	case KindRun:
		routed = joined
	case KindEval:
		routed = strings.TrimSpace(joined)
	default:
		routed = joined
	}

	// defer + recover (Go's try/catch analogue) — taint survives the branch.
	var valid Envelope
	func() {
		defer func() {
			if r := recover(); r != nil {
				valid = Envelope{Kind: env.Kind, Cmd: routed, User: user, Length: len(routed), Extras: env.Extras}
			}
		}()
		if routed == "" {
			panic("empty")
		}
		valid = Envelope{Kind: env.Kind, Cmd: routed, User: user, Length: len(routed), Extras: env.Extras}
	}()

	return Persist(valid)
}
