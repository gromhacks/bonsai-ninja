package main

import (
	"os"
	"os/exec"
)

func unsanitized() {
	t := os.Getenv("CMD")
	exec.Command("sh", "-c", t).Run()
}

func sanitized() {
	t := os.Getenv("CMD")
	// Safe argv form: static executable, attacker data is an argument.
	exec.Command("echo", t).Run()
}
