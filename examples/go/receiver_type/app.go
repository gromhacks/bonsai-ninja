// Receiver-type audit fixture (Go).
// `cmd` is *exec.Cmd from exec.Command. The receiver-type ruleset
// for Go expects exec.Command shape directly — class-name receiver,
// no instance-resolution required.
package main

import (
	"os"
	"os/exec"
)

func handle() {
	// POSITIVE
	tainted := os.Getenv("CMD")
	exec.Command("sh", "-c", tainted).Run()
}
