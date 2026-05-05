package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ---------------------------------------------------------------------------
// deep_flow_chain.go -- Entry point for a 35-step deep cross-file flow chain.
//
// User input from bufio.Scanner flows through parse -> validate -> transform
// -> registry lookup -> executor -> exec.Command (SINK).
//
// All type/function names prefixed with Dfc to avoid cross-file collisions.
// ---------------------------------------------------------------------------

// DfcCommandParser parses raw user input into structured command tokens.
type DfcCommandParser struct {
	delimiter string
	rawBuffer string
}

func DfcNewCommandParser() *DfcCommandParser {
	return &DfcCommandParser{
		delimiter: "::",
		rawBuffer: "",
	}
}

// Step 1: read user input (SOURCE)
func (p *DfcCommandParser) ReadInput() string {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter plugin command: ")
	scanner.Scan()
	rawText := scanner.Text()
	// Step 2: store in struct field
	p.rawBuffer = rawText
	return p.rawBuffer
}

// Step 3-4: tokenize into parts
func (p *DfcCommandParser) Tokenize(text string) map[string]string {
	parts := strings.Split(strings.TrimSpace(text), p.delimiter)
	pluginName := ""
	if len(parts) > 0 {
		pluginName = parts[0]
	}
	action := "default"
	if len(parts) > 1 {
		action = parts[1]
	}
	arguments := ""
	if len(parts) > 2 {
		arguments = strings.Join(parts[2:], p.delimiter)
	}
	tokens := map[string]string{
		"plugin_name": pluginName,
		"action":      action,
		"arguments":   arguments,
	}
	return tokens
}

// Step 5-7: normalize tokens into a command descriptor
func (p *DfcCommandParser) Normalize(tokens map[string]string) map[string]string {
	// Step 5: normalize plugin name
	pluginID := strings.ToLower(strings.ReplaceAll(tokens["plugin_name"], "-", "_"))
	// Step 6: normalize action
	normalizedAction := strings.TrimSpace(tokens["action"])
	// Step 7: combine into descriptor
	descriptor := map[string]string{
		"id":           pluginID,
		"action":       normalizedAction,
		"args":         tokens["arguments"],
		"full_command": pluginID + "." + normalizedAction,
	}
	return descriptor
}

// DfcInputValidator validates parsed command descriptors.
type DfcInputValidator struct {
	errors []string
}

// Step 8-10: validate the descriptor
func (v *DfcInputValidator) CheckFormat(descriptor map[string]string) map[string]string {
	// Step 8: extract command string
	cmdStr := descriptor["full_command"]
	// Step 9: extract arguments
	cmdArgs := descriptor["args"]
	isValid := "true"
	if len(cmdStr) == 0 {
		isValid = "false"
	}
	// Step 10: build validated payload (no real sanitization -- vulnerable)
	validated := map[string]string{
		"command":    cmdStr,
		"parameters": cmdArgs,
		"is_valid":   isValid,
	}
	return validated
}

// Step 11-13: wrap validated payload into a DfcRequestContext
func dfcBuildRequest(validated map[string]string) *DfcRequestContext {
	// Step 11: extract fields
	command := validated["command"]
	params := validated["parameters"]
	// Step 12: create context object (cross-file, into deep_flow_helpers.go)
	ctx := DfcNewRequestContext(command, params)
	// Step 13: attach metadata
	ctx.Metadata["origin"] = "cli"
	ctx.Metadata["validated"] = validated["is_valid"]
	return ctx
}

// Step 14-16: run middleware chain on the request context
func dfcApplyMiddleware(ctx *DfcRequestContext) *DfcRequestContext {
	// Step 14: create middleware chain (cross-file)
	chain := DfcNewMiddlewareChain()
	// Step 15: register built-in middleware
	chain.AddLoggingMiddleware()
	chain.AddTransformMiddleware()
	// Step 16: process through chain
	processedCtx := chain.Process(ctx)
	return processedCtx
}

// Step 22-26: dispatch processed context to the executor
func dfcDispatchToExecutor(processedCtx *DfcRequestContext) string {
	// Step 22: extract processed command
	finalCommand := processedCtx.Command
	finalParams := processedCtx.Params
	// Step 23: build execution string
	execString := finalCommand + " " + finalParams
	// Step 24: create registry and look up plugin
	registry := DfcNewCommandRegistry()
	pluginName := strings.Split(finalCommand, ".")[0]
	handler := registry.GetHandler(pluginName)
	// Step 25: wrap in executor (cross-file, into deep_flow_sink.go)
	executor := DfcNewPluginExecutor(handler)
	// Step 26: pass to executor for final processing
	result := executor.PrepareAndRun(execString, processedCtx.Metadata)
	return result
}

func main() {
	parser := DfcNewCommandParser()
	validator := &DfcInputValidator{}

	// Steps 1-2: read input
	raw := parser.ReadInput()
	// Steps 3-4: tokenize
	tokens := parser.Tokenize(raw)
	// Steps 5-7: normalize
	descriptor := parser.Normalize(tokens)
	// Steps 8-10: validate
	validated := validator.CheckFormat(descriptor)
	// Steps 11-13: build request context
	ctx := dfcBuildRequest(validated)
	// Steps 14-21: apply middleware
	processed := dfcApplyMiddleware(ctx)
	// Steps 22-35: dispatch and execute
	result := dfcDispatchToExecutor(processed)

	if result != "" {
		fmt.Println("Execution result: " + result)
	}
}
