package main

import (
	"context"
	"os"
	"sync"
)

// Direct close-then-read.
func use_after_close(f *os.File) ([]byte, error) {
	f.Close()
	buf := make([]byte, 32)
	_, err := f.Read(buf)
	return buf, err
}

// Conditional close on the error path; later read still reachable.
func conditional_close(f *os.File, fail bool) (int, error) {
	if fail {
		f.Close()
	}
	buf := make([]byte, 16)
	return f.Read(buf)
}

// Cancel context, then continue using it.
func use_after_cancel(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	cancel()
	ctx.Done()
}

// Unlock-then-use — `mu.Read()` is contrived but mirrors the
// adapter-level transition shape we model.
func unlock_then_use(mu *sync.Mutex) {
	mu.Unlock()
	mu.Lock()
}

func main() {}
