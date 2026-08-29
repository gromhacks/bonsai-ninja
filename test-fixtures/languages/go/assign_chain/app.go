// Assignment-chain audit fixture (Go).
package main

import (
	"net/http"
	"os/exec"
)

const ConstOk = "ls /tmp"

func passthrough(x string) string { return x }
func wrap(x string) string        { return "wrapped:" + x }
func combine(acc, item string) string {
	return acc + ":" + item
}

type Bag struct {
	Payload string
}

func chainSimple(r *http.Request) {
	// POSITIVE
	tmp := r.URL.Query().Get("c1")
	exec.Command("sh", "-c", tmp).Run()
}

func chainMultiHop(r *http.Request) {
	// POSITIVE
	t1 := r.URL.Query().Get("c2")
	t2 := passthrough(t1)
	t3 := wrap(t2)
	t4 := passthrough(t3)
	exec.Command("sh", "-c", t4).Run()
}

func chainBranchJoin(r *http.Request, cond bool) {
	// POSITIVE
	var t string
	if cond {
		t = r.URL.Query().Get("c3")
	} else {
		t = "safe-static"
	}
	exec.Command("sh", "-c", t).Run()
}

func chainLoopCarried(r *http.Request, items []string) {
	// POSITIVE
	acc := r.URL.Query().Get("c4")
	for _, item := range items {
		acc = combine(acc, item)
	}
	exec.Command("sh", "-c", acc).Run()
}

func chainFieldWrite(r *http.Request) {
	// POSITIVE
	bag := Bag{}
	bag.Payload = r.URL.Query().Get("c5")
	exec.Command("sh", "-c", bag.Payload).Run()
}

func chainSubscriptWrite(r *http.Request) {
	// POSITIVE
	cmds := map[string]string{}
	cmds["x"] = r.URL.Query().Get("c6")
	exec.Command("sh", "-c", cmds["x"]).Run()
}

func chainCleanConstant(r *http.Request) {
	// NEGATIVE
	_ = r.URL.Query().Get("ignored")
	exec.Command("sh", "-c", ConstOk).Run()
}

func chainCrossFile(r *http.Request) {
	// POSITIVE
	t := r.URL.Query().Get("c9")
	RunInOtherFile(t)
}
