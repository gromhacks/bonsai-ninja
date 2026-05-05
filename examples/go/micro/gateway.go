package micro

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

// HandleRequest is the named entry point for cross-module flow
// analysis. It directly invokes the source → sink chain so the
// tree-sitter-captured call graph has edges
// `HandleRequest → GetUser / UpdateUser → ...` without hiding them
// inside a returned closure (the previous shape used
// `http.HandlerFunc` which buried the interesting calls in a
// nested func literal, and tree-sitter didn't attribute them to
// the outer decl).
func HandleRequest(db *sql.DB, token string, action string) map[string]interface{} {
	user, _ := GetUser(db, token)              // flows to SQL injection
	result, _ := UpdateUser(db, token, action) // flows to command injection
	return map[string]interface{}{"user": user, "result": result}
}

// Router is the HTTP adapter that pulls params out of the request
// and delegates into `HandleRequest`. Tree-sitter treats this
// function's inner closure as opaque — that's fine, all the
// interesting edges live in `HandleRequest` above.
func Router(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")   // source: user input
		action := r.URL.Query().Get("action") // source: user input
		_ = json.NewEncoder(w).Encode(HandleRequest(db, token, action))
	}
}
