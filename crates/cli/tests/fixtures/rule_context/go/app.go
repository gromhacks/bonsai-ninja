package app
import (
    "net/http"
    "os/exec"
    "strconv"
)
func quoted(w http.ResponseWriter, r *http.Request) {
    exec.Command("sh", "-c", "echo " + strconv.Quote(r.FormValue("cmd"))).Run()
}
func direct(w http.ResponseWriter, r *http.Request) {
    exec.Command("sh", "-c", "echo " + r.FormValue("cmd")).Run()
}
