package main

import (
	"os"
	"os/exec"
)

func taintOneLeg(cond bool) {
	var x string
	if cond {
		x = os.Getenv("CMD")
	} else {
		x = "safe-static"
	}
	exec.Command("sh", "-c", x).Run()
}

func taintOverwritten(cond bool) {
	x := os.Getenv("CMD")
	if cond {
		x = "clean-then"
	} else {
		x = "clean-else"
	}
	exec.Command("sh", "-c", x).Run()
}
