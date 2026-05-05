// Go has no try/catch — defer / recover is the closest. Use recover.
package main

import (
	"os"
	"os/exec"
)

func taintedThroughTry() {
	defer func() {
		_ = recover()
	}()
	t := os.Getenv("CMD")
	exec.Command("sh", "-c", t).Run()
}
