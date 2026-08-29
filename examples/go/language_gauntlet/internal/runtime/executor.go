package runtime

import execpkg "os/exec"

func Execute(cmd string) int {
	// SINK -- shell wrapper with a tainted command / CWE-78.
	_ = execpkg.Command("/bin/sh", "-c", cmd).Run()
	return 0
}

func CleanTwin() int {
	// NEGATIVE -- the constant argument must remain untainted.
	_ = execpkg.Command("/bin/sh", "-c", "echo clean").Run()
	return 0
}
