// Compiler architecture test cases for the tree-sitter-sast flow engine.
//
// Each section tests a specific capability with both positive (flow expected)
// and negative (no flow expected) scenarios.
package main

import (
	"database/sql"
	"fmt"
	"os/exec"
	"strings"
)

// ---------------------------------------------------------------------------
// 1. BRANCH-AWARE KILL ANALYSIS
// ---------------------------------------------------------------------------

// [NO FLOW EXPECTED] Both branches sanitize
func branchKillBothPaths(userInput string) {
	var cmd string
	if len(userInput) > 100 {
		cmd = "default_command"
	} else {
		cmd = "safe_fallback"
	}
	exec.Command(cmd).Run() // safe: both paths overwrite
}

// [FLOW EXPECTED] Only one branch kills taint
func branchKillOnePath(userInput string) {
	cmd := userInput
	if len(cmd) > 100 {
		cmd = "truncated"
	}
	// else: cmd still holds userInput
	exec.Command(cmd).Run() // tainted
}

// [FLOW EXPECTED] Switch without default
func branchKillSwitch(userInput string) {
	query := userInput
	switch query[0] {
	case 'a':
		query = "SELECT * FROM a"
	case 'b':
		query = "SELECT * FROM b"
		// no default: query keeps userInput for other chars
	}
	exec.Command("sqlite3", query).Run()
}

// ---------------------------------------------------------------------------
// 2. INTERPROCEDURAL KILL (2+ levels deep)
// ---------------------------------------------------------------------------

func sanitize(value string) string {
	value = strings.ReplaceAll(value, "'", "")
	value = strings.ReplaceAll(value, ";", "")
	value = strings.ReplaceAll(value, "--", "")
	return value
}

func wrapSanitize(value string) string {
	return sanitize(value)
}

// [NO FLOW EXPECTED] Sanitizer applied
func interproceduralKillDirect(userInput string, db *sql.DB) {
	clean := sanitize(userInput)
	db.Exec(fmt.Sprintf("SELECT * FROM t WHERE x = '%s'", clean))
}

// [NO FLOW EXPECTED] Sanitizer 2 levels deep
func interproceduralKillTwoLevels(userInput string, db *sql.DB) {
	clean := wrapSanitize(userInput)
	db.Exec(fmt.Sprintf("SELECT * FROM t WHERE x = '%s'", clean))
}

// [FLOW EXPECTED] No sanitizer
func interproceduralNoKill(userInput string, db *sql.DB) {
	db.Exec(fmt.Sprintf("SELECT * FROM t WHERE x = '%s'", userInput))
}

// ---------------------------------------------------------------------------
// 3. FIELD-SENSITIVE TRACKING
// ---------------------------------------------------------------------------

type Config struct {
	Command string
	Label   string
}

// [FLOW EXPECTED] Tainted field flows to sink
func fieldSensitiveTainted(userInput string) {
	cfg := Config{Command: userInput, Label: "safe"}
	exec.Command(cfg.Command).Run()
}

// [NO FLOW EXPECTED] Only safe field used
func fieldSensitiveSafe(userInput string) {
	cfg := Config{Command: userInput, Label: "safe"}
	exec.Command(cfg.Label).Run()
}

// [NO FLOW EXPECTED] Tainted field overwritten
func fieldSensitiveOverwrite(userInput string) {
	cfg := Config{Command: userInput}
	cfg.Command = "hardcoded_safe"
	exec.Command(cfg.Command).Run()
}

// ---------------------------------------------------------------------------
// 4. MULTI-RETURN PRECISION (Go-specific)
// ---------------------------------------------------------------------------

func fetchData(source string) (string, error) {
	return source, nil
}

// [FLOW EXPECTED] Position 0 carries taint
func multiReturnTainted(userInput string) {
	data, _ := fetchData(userInput)
	exec.Command(data).Run()
}

// [NO FLOW EXPECTED] Position 1 (error) does not carry call taint
func multiReturnSafe(userInput string) {
	_, err := fetchData(userInput)
	if err != nil {
		exec.Command(err.Error()).Run()
	}
}

// ---------------------------------------------------------------------------
// 5. CHANNEL TAINT PROPAGATION (Go-specific)
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Taint flows through channel
func channelTaint(userInput string) {
	ch := make(chan string, 1)
	ch <- userInput
	cmd := <-ch
	exec.Command(cmd).Run()
}

// ---------------------------------------------------------------------------
// 6. GOROUTINE CLOSURE CAPTURE
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Closure captures tainted variable
func goroutineClosureTaint(userInput string) {
	done := make(chan bool)
	go func() {
		exec.Command(userInput).Run() // captures userInput
		done <- true
	}()
	<-done
}

// ---------------------------------------------------------------------------
// 7. NAMED RETURN VALUES (Go-specific)
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Named return carries taint
func namedReturn(userInput string) (result string) {
	result = userInput
	return // bare return uses named value
}

func namedReturnSink(userInput string) {
	cmd := namedReturn(userInput)
	exec.Command(cmd).Run()
}

// ---------------------------------------------------------------------------
// 8. INTERFACE DISPATCH
// ---------------------------------------------------------------------------

type Executor interface {
	Execute(cmd string) error
}

type SafeExecutor struct{}

func (s SafeExecutor) Execute(cmd string) error {
	fmt.Println("Would execute:", cmd) // safe
	return nil
}

type UnsafeExecutor struct{}

func (u UnsafeExecutor) Execute(cmd string) error {
	return exec.Command(cmd).Run() // dangerous
}

// [FLOW EXPECTED]
func typeTrackedUnsafe(userInput string) {
	var executor Executor = UnsafeExecutor{}
	executor.Execute(userInput)
}

// [NO FLOW EXPECTED]
func typeTrackedSafe(userInput string) {
	var executor Executor = SafeExecutor{}
	executor.Execute(userInput)
}

// ---------------------------------------------------------------------------
// 9. PARAMETER SOURCE SYNTHESIS
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] External entry point
func HandleWebhook(payload string, signature string) {
	exec.Command("process", payload).Run()
}

// ---------------------------------------------------------------------------
// 10. CROSS-METHOD STRUCT FIELD TAINT
// ---------------------------------------------------------------------------

type Pipeline struct {
	data string
}

func (p *Pipeline) Ingest(raw string) {
	p.data = raw
}

func (p *Pipeline) Process() {
	exec.Command(p.data).Run()
}

// [FLOW EXPECTED] Taint flows through struct field across methods
func crossMethodFieldTaint(userInput string) {
	p := &Pipeline{}
	p.Ingest(userInput)
	p.Process()
}

// ---------------------------------------------------------------------------
// 11. DEFER WITH TAINT (Go-specific)
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Deferred function uses tainted variable
func deferTaint(userInput string) {
	cmd := userInput
	defer exec.Command(cmd).Run()
	// cmd is captured at defer registration
}

// ---------------------------------------------------------------------------
// 12. SLICE APPEND TAINT
// ---------------------------------------------------------------------------

// [FLOW EXPECTED] Taint flows through slice append
func sliceAppendTaint(userInput string, db *sql.DB) {
	parts := []string{}
	parts = append(parts, userInput)
	query := strings.Join(parts, " ")
	db.Exec(query)
}
