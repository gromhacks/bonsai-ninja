// Go sanitizer-fixture — parallel handlers per sink family.
package sanitizer_test

import (
	"crypto/subtle"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os/exec"
)

// --- Command injection ----------------------------------------------------

func CmdRaw(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	out, _ := exec.Command("sh", "-c", "ping "+cmd).Output()
	w.Write(out)
}

func CmdSafe(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	// argv-form without a shell wrapper: `cmd` becomes a single arg,
	// not a shell command. This is Go's canonical cmdi mitigation.
	out, _ := exec.Command("ping", cmd).Output()
	w.Write(out)
}

// --- SQL injection --------------------------------------------------------

func SqlRaw(db *sql.DB, userID string) *sql.Rows {
	rows, _ := db.Query("SELECT * FROM users WHERE id = '" + userID + "'")
	return rows
}

func SqlSafe(db *sql.DB, userID string) *sql.Rows {
	stmt, _ := db.Prepare("SELECT * FROM users WHERE id = $1")
	rows, _ := stmt.Query(userID)
	return rows
}

// --- XSS ------------------------------------------------------------------

func XssRaw(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<p>Hello, %s</p>", name)
}

func XssSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	safe := template.HTMLEscapeString(name)
	fmt.Fprintf(w, "<p>Hello, %s</p>", safe)
}

// --- Open redirect --------------------------------------------------------

func RedirectSafe(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("to")
	safe := url.QueryEscape(target)
	http.Redirect(w, r, "/next?to="+safe, http.StatusFound)
}

// --- Timing attack --------------------------------------------------------

func TokenEqRaw(given, expected string) bool {
	return given == expected
}

func TokenEqSafe(given, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(given), []byte(expected)) == 1
}
