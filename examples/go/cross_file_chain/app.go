// Cross-file argument flow audit fixture (Go).
package main

import "os"

func Handler() {
	// POSITIVE
	user := os.Getenv("CMD")
	RunPipeline(user)
}

func HandlerSplit() {
	// POSITIVE
	user := os.Getenv("FROM")
	flag := os.Getenv("FLAG")
	RunPipeline(user + ":" + flag)
}
