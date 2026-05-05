package main

import execpkg "os/exec"

// Execute — SINK, os/exec.Command run through /bin/sh -c.
func Execute(cmd string) int {
	// go.cmdi.exec_command · severity=critical · CWE-78
	_ = execpkg.Command("/bin/sh", "-c", cmd).Run()
	return 0
}

func cleanTwin() int {
	// NEGATIVE — same sink kind with a constant argument must not report.
	_ = execpkg.Command("/bin/sh", "-c", "echo clean").Run()
	return 0
}
