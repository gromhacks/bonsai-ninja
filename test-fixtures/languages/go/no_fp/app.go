package main

import (
	"os"
	"os/exec"
	"strings"
)

const ConstOk = "ls /tmp"

func decoy() {
	_ = os.Getenv("IGNORED")
	exec.Command("sh", "-c", ConstOk).Run()
}

func unrelatedChain() string {
	a := "hello"
	return strings.ToUpper(a)
}
