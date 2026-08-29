package main

import (
	"context"
	"fmt"
	"net/http"

	domainmodel "example.com/bonsai/language-gauntlet/internal/domain"
	"example.com/bonsai/language-gauntlet/internal/pipeline"
)

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// SOURCE -- net/http query input.
	raw := r.URL.Query().Get("cmd")
	user := r.Header.Get("X-User")
	envelope := domainmodel.NewEnvelope(raw, user)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	result := pipeline.Orchestrate(ctx, envelope)
	fmt.Fprintln(w, result)
}

func main() {
	http.HandleFunc("/run", handleRequest)
	_ = http.ListenAndServe(":8080", nil)
}
