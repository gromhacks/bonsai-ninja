package main

import "strings"

func TransformAndForward(value string) {
	upper := strings.ToUpper(value)
	Execute(upper)
}
