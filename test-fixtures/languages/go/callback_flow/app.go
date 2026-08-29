package main

import (
	"os"
	"os/exec"
)

func executor(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}

func run(cb func(string), value string) {
	cb(value)
}

func passToCallback() {
	t := os.Getenv("CMD")
	run(executor, t)
}
