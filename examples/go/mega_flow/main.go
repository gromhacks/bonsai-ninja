package main

import (
	"context"
	"fmt"
	"net/http"
)

// mega_flow Go entry — an HTTP handler reads r.URL.Query().Get("cmd"),
// then dispatches through a pipeline that exercises every idiomatic
// Go flow construct (goroutines, channels, defer, select, context,
// type assertions, interfaces, closures, variadic).

// Kind — named string type used as a typed enum.
type Kind string

const (
	KindRun  Kind = "run"
	KindEval Kind = "eval"
)

// Envelope — struct carrying the tainted cmd field.
type Envelope struct {
	Kind   Kind
	Cmd    string
	User   string
	Length int
	Extras []string
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// SOURCE — net/http r.URL.Query().
	raw := r.URL.Query().Get("cmd")
	user := r.Header.Get("X-User")

	env := Envelope{
		Kind:   KindRun,
		Cmd:    raw,
		User:   user,
		Length: len(raw),
		Extras: []string{raw},
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	out := Orchestrate(ctx, env)
	fmt.Fprintln(w, out)
}

func main() {
	http.HandleFunc("/run", handleRequest)
	http.ListenAndServe(":8080", nil)
}
