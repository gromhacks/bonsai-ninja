package main

import "os/exec"

func Execute(cmd string) {
	// POSITIVE (terminal cross-file sink)
	exec.Command("sh", "-c", cmd).Run()
}
