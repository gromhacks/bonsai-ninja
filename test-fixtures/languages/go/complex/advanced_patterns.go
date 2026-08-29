package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// ---------------------------------------------------------------------------
// advanced_patterns.go -- Go-specific syntax patterns for taint analysis
//
// Each vulnerability chain exercises a different Go language feature that
// taint must propagate through. Sources are always HTTP request values;
// sinks are db.Exec, exec.Command, os.Open, or fmt.Fprintf with user data.
// ---------------------------------------------------------------------------

// --- Helpers ---------------------------------------------------------------

type WorkItem struct {
	Payload string
	Done    bool
}

type Notifier interface {
	Send(msg string) error
}

type EmailNotifier struct {
	db *sql.DB
}

func (e *EmailNotifier) Send(msg string) error {
	// VULN 8b sink: interface dispatch lands here, msg is tainted
	// Chain: r.FormValue -> embedded field -> interface dispatch -> db.Exec
	_, err := e.db.Exec("INSERT INTO notifications (message) VALUES ('" + msg + "')")
	return err
}

type SlackNotifier struct{}

func (s *SlackNotifier) Send(msg string) error {
	fmt.Println("slack:", msg)
	return nil
}

// BaseService is embedded into AdvancedHandler to exercise struct embedding.
type BaseService struct {
	db *sql.DB
}

func (b *BaseService) RunRawSQL(query string) (*sql.Rows, error) {
	// VULN 8a sink: struct embedding, taint flows through embedded method
	return b.db.Query(query)
}

// AdvancedHandler embeds BaseService so callers can invoke RunRawSQL directly.
type AdvancedHandler struct {
	BaseService
	notifier Notifier
}

func NewAdvancedHandler(db *sql.DB) *AdvancedHandler {
	return &AdvancedHandler{
		BaseService: BaseService{db: db},
		notifier:    &EmailNotifier{db: db},
	}
}

// ---------------------------------------------------------------------------
// VULN 1 -- Channel send/receive flowing taint
//
// Chain: r.URL.Query().Get("q") -> ch <- q -> val := <-ch -> db.Exec(val)
// The tainted query parameter is sent into a channel, received on the other
// side, and used in an unsanitized SQL exec.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) ChannelFlow(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	ch := make(chan string, 1)
	ch <- q
	val := <-ch
	h.db.Exec("DELETE FROM cache WHERE key = '" + val + "'")
	fmt.Fprintf(w, "purged")
}

// ---------------------------------------------------------------------------
// VULN 2 -- Goroutine + closure capture
//
// Chain: r.FormValue("cmd") -> captured by goroutine closure -> exec.Command
// The closure captures `command` from the outer scope and executes it inside
// a goroutine. Taint must propagate through the closure capture.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) GoroutineClosure(w http.ResponseWriter, r *http.Request) {
	command := r.FormValue("cmd")
	done := make(chan []byte, 1)
	go func() {
		// VULN 2 sink: closure captures `command` from enclosing scope
		cmd := exec.Command("sh", "-c", command)
		out, _ := cmd.Output()
		done <- out
	}()
	result := <-done
	w.Write(result)
}

// ---------------------------------------------------------------------------
// VULN 3 -- Multiple return values (val, err)
//
// Chain: r.URL.Query().Get("path") -> fetchPath(path) returns (string, error)
//        -> content (first return value) -> os.Open(content)
// Taint flows through the first element of a multi-return.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) MultiReturn(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	resolved, err := resolvePath(path)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// VULN 3 sink: resolved still carries taint from path
	f, err := os.Open(resolved)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	defer f.Close()
	fmt.Fprintf(w, "opened %s", resolved)
}

func resolvePath(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty path")
	}
	// No sanitization -- passes taint through
	return "/data/" + input, nil
}

// ---------------------------------------------------------------------------
// VULN 4 -- Type switch (switch v := x.(type))
//
// Chain: json.NewDecoder(r.Body).Decode(&raw) -> type switch extracts string
//        -> db.Exec with that string
// Taint must propagate through the type assertion variable in each case arm.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) TypeSwitchFlow(w http.ResponseWriter, r *http.Request) {
	var raw interface{}
	json.NewDecoder(r.Body).Decode(&raw)

	var query string
	switch v := raw.(type) {
	case string:
		query = v
	case map[string]interface{}:
		if q, ok := v["query"]; ok {
			query = fmt.Sprintf("%v", q)
		}
	default:
		query = fmt.Sprintf("%v", v)
	}
	// VULN 4 sink: query derived from decoded body through type switch
	h.db.Exec("SELECT * FROM data WHERE filter = '" + query + "'")
	fmt.Fprintf(w, "ok")
}

// ---------------------------------------------------------------------------
// VULN 5 -- Select statement
//
// Chain: r.FormValue("host") -> sent into one of two channels -> select
//        receives from whichever is ready -> exec.Command("ping", target)
// Taint propagates through a select receiving from multiple channels.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) SelectFlow(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	primary := make(chan string, 1)
	fallback := make(chan string, 1)
	primary <- host

	var target string
	select {
	case target = <-primary:
		// received from primary
	case target = <-fallback:
		// received from fallback
	}
	// VULN 5 sink: target carries taint from host
	cmd := exec.Command("ping", "-c", "1", target)
	out, _ := cmd.Output()
	w.Write(out)
}

// ---------------------------------------------------------------------------
// VULN 6 -- Named return values
//
// Chain: r.URL.Query().Get("filter") -> buildNamedFilter sets named return
//        -> caller uses returned value in db.Exec
// Taint flows through a named return variable that is set in the function
// body and returned implicitly via bare `return`.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) NamedReturnFlow(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	clause := buildNamedFilter(filter)
	// VULN 6 sink: clause carries taint from filter
	h.db.Exec("SELECT * FROM events WHERE " + clause)
	fmt.Fprintf(w, "done")
}

func buildNamedFilter(input string) (result string) {
	result = "status = 'active' AND name LIKE '%" + input + "%'"
	return
}

// ---------------------------------------------------------------------------
// VULN 7 -- Defer + closure
//
// Chain: r.FormValue("tag") -> deferred closure captures `tag` -> at function
//        exit the closure runs db.Exec with tainted tag
// Taint must propagate through a deferred closure's captured variables.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) DeferClosure(w http.ResponseWriter, r *http.Request) {
	tag := r.FormValue("tag")
	defer func() {
		// VULN 7 sink: deferred closure captures `tag`, executes at exit
		h.db.Exec("INSERT INTO audit_log (tag) VALUES ('" + tag + "')")
	}()
	fmt.Fprintf(w, "processing tag=%s", tag)
}

// ---------------------------------------------------------------------------
// VULN 8a -- Struct embedding
//
// Chain: r.URL.Query().Get("table") -> direct call to embedded method
//        h.RunRawSQL(query) which is defined on BaseService
// Taint flows through an embedded struct's method.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) EmbeddedMethodCall(w http.ResponseWriter, r *http.Request) {
	table := r.URL.Query().Get("table")
	query := "SELECT * FROM " + table
	// RunRawSQL is promoted from the embedded BaseService
	rows, err := h.RunRawSQL(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "queried %s", table)
}

// ---------------------------------------------------------------------------
// VULN 8b -- Interface dispatch
//
// Chain: r.FormValue("message") -> h.notifier.Send(msg) -> dispatches to
//        EmailNotifier.Send -> db.Exec with tainted msg
// Taint flows through an interface method call to the concrete implementation.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) InterfaceDispatch(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("message")
	err := h.notifier.Send(msg)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "notified")
}

// ---------------------------------------------------------------------------
// VULN 9 -- strings.Builder chain
//
// Chain: r.URL.Query().Get("name") -> strings.Builder.WriteString (x3) ->
//        builder.String() -> db.Exec
// Taint propagates through a Builder's accumulated writes to String().
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) BuilderChain(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	var b strings.Builder
	b.WriteString("UPDATE users SET last_login = NOW() WHERE name = '")
	b.WriteString(name)
	b.WriteString("'")
	stmt := b.String()
	// VULN 9 sink: stmt built with tainted name via strings.Builder
	h.db.Exec(stmt)
	fmt.Fprintf(w, "updated")
}

// ---------------------------------------------------------------------------
// VULN 10 -- Variadic function (...string)
//
// Chain: r.FormValue("a"), r.FormValue("b"), r.FormValue("c") -> joinParts
//        (variadic) -> concatenated -> db.Exec
// Taint must flow through variadic parameters into the joined result.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) VariadicFlow(w http.ResponseWriter, r *http.Request) {
	a := r.FormValue("a")
	b := r.FormValue("b")
	c := r.FormValue("c")
	clause := joinParts(" AND ", a, b, c)
	// VULN 10 sink: clause built from tainted variadic args
	h.db.Exec("SELECT * FROM records WHERE " + clause)
	fmt.Fprintf(w, "ok")
}

func joinParts(sep string, parts ...string) string {
	return strings.Join(parts, sep)
}

// ---------------------------------------------------------------------------
// VULN 11 -- If-init statement (if val := expr; cond)
//
// Chain: r.URL.Query().Get("file") -> if-init assignment with condition ->
//        os.Open(validated) inside the if body
// Taint propagates through the short variable in an if-init statement.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) IfInitFlow(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	if validated := validateFilename(file); validated != "" {
		// VULN 11 sink: validated still tainted (validateFilename is a no-op)
		f, err := os.Open(validated)
		if err != nil {
			http.Error(w, "not found", 404)
			return
		}
		defer f.Close()
		fmt.Fprintf(w, "opened %s", validated)
	}
}

func validateFilename(name string) string {
	// Bug: no actual sanitization
	if name == "" {
		return ""
	}
	return name
}

// ---------------------------------------------------------------------------
// VULN 12 -- Goroutine channel pipeline (multi-stage)
//
// Chain: r.FormValue("expr") -> stage1 channel -> transform -> stage2 channel
//        -> db.Exec. A two-stage pipeline where taint must cross two channel
//        boundaries.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) PipelineFlow(w http.ResponseWriter, r *http.Request) {
	expr := r.FormValue("expr")

	stage1 := make(chan string, 1)
	stage2 := make(chan string, 1)

	// Stage 1: prefix the expression
	go func() {
		val := <-stage1
		stage2 <- "computed_" + val
	}()

	stage1 <- expr
	result := <-stage2
	// VULN 12 sink: result carries taint from expr through two channels
	h.db.Exec("INSERT INTO results (expr) VALUES ('" + result + "')")
	fmt.Fprintf(w, "computed")
}

// ---------------------------------------------------------------------------
// VULN 13 -- Range over slice with tainted elements
//
// Chain: json.NewDecoder(r.Body).Decode(&items) -> range loop -> each item
//        used in db.Exec
// Taint propagates through range iteration over a decoded slice.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) RangeFlow(w http.ResponseWriter, r *http.Request) {
	var items []string
	json.NewDecoder(r.Body).Decode(&items)
	for _, item := range items {
		// VULN 13 sink: each item is tainted from the decoded body
		h.db.Exec("INSERT INTO batch (value) VALUES ('" + item + "')")
	}
	fmt.Fprintf(w, "inserted %d items", len(items))
}

// ---------------------------------------------------------------------------
// VULN 14 -- Map lookup with tainted value
//
// Chain: r.URL.Query().Get("key") -> map[key] retrieves a previously stored
//        tainted value -> db.Exec. Taint stored in a map and retrieved later.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) MapLookupFlow(w http.ResponseWriter, r *http.Request) {
	data := make(map[string]string)
	data["user"] = r.URL.Query().Get("user")
	data["action"] = r.URL.Query().Get("action")

	userVal := data["user"]
	// VULN 14 sink: userVal retrieved from map still carries taint
	h.db.Exec("INSERT INTO activity (user_name) VALUES ('" + userVal + "')")
	fmt.Fprintf(w, "logged %s", userVal)
}

// ---------------------------------------------------------------------------
// VULN 15 -- Struct field assignment and read-back
//
// Chain: r.FormValue("payload") -> WorkItem{Payload: payload} -> item.Payload
//        -> exec.Command. Taint flows through struct field write then read.
// ---------------------------------------------------------------------------

func (h *AdvancedHandler) StructFieldFlow(w http.ResponseWriter, r *http.Request) {
	payload := r.FormValue("payload")
	item := WorkItem{Payload: payload}
	// VULN 15 sink: item.Payload carries taint from FormValue
	cmd := exec.Command("sh", "-c", item.Payload)
	out, _ := cmd.Output()
	w.Write(out)
}

// ============================================================
// ADDITIONAL PATTERNS - Error wrapping, context propagation
// ============================================================

// Error wrapping with taint
func errorWrapFlow(input string) error {
	result, err := processData(input)
	if err != nil {
		return fmt.Errorf("failed to process %s: %w", input, err)
	}
	exec.Command(result).Run()
	return nil
}

// Context value propagation
func contextFlow(ctx context.Context) {
	cmd := ctx.Value("user_command").(string)
	exec.Command(cmd).Run()  // taint from context value
}

// Slice append propagation
func sliceFlow(inputs []string) {
	var commands []string
	for _, input := range inputs {
		commands = append(commands, input)
	}
	for _, cmd := range commands {
		exec.Command(cmd).Run()  // taint through slice
	}
}

// Map propagation
func mapFlow(input string) {
	config := make(map[string]string)
	config["cmd"] = input
	exec.Command(config["cmd"]).Run()  // taint through map
}
