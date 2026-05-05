package main

import "os/exec"

func RunInOtherFile(cmd string) {
	// POSITIVE (cross-file)
	exec.Command("sh", "-c", cmd).Run()
}
