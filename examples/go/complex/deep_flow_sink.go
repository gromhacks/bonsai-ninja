package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// ---------------------------------------------------------------------------
// deep_flow_sink.go -- Final executor for deep flow chain (contains SINK).
//
// Receives processed command strings and executes them via exec.Command.
// The taint chain terminates here.
//
// Contains: DfcPluginExecutor, DfcExecutionConfig, DfcCommandRunner
// ---------------------------------------------------------------------------

// DfcPluginExecutor executes plugin commands after final preparation.
type DfcPluginExecutor struct {
	HandlerName string
	Config      *DfcExecutionConfig
}

func DfcNewPluginExecutor(handlerName string) *DfcPluginExecutor {
	// Step 25 (from caller): store handler name
	return &DfcPluginExecutor{
		HandlerName: handlerName,
		Config:      DfcNewExecutionConfig(),
	}
}

func (pe *DfcPluginExecutor) PrepareAndRun(execString string, metadata map[string]string) string {
	// Step 27: build the shell prefix
	shellPrefix := pe.Config.GetPrefix()
	// Step 28: combine handler name into command
	handlerCmd := pe.HandlerName + " " + execString
	// Step 29: apply metadata-based transformations
	if metadata["transformed"] == "true" {
		handlerCmd = handlerCmd + " --transformed"
	}
	// Step 30: wrap in shell invocation
	fullShellCmd := shellPrefix + " -c '" + handlerCmd + "'"
	// Step 31: pass to the runner
	runner := DfcNewCommandRunner()
	result := runner.Execute(fullShellCmd)
	return result
}

func (pe *DfcPluginExecutor) PrepareBatch(commands []string, metadata map[string]string) []string {
	results := make([]string, 0)
	for _, cmd := range commands {
		combined := pe.HandlerName + " " + cmd
		if metadata["origin"] == "cli" {
			combined = combined + " --interactive"
		}
		runner := DfcNewCommandRunner()
		res := runner.Execute(combined)
		results = append(results, res)
	}
	return results
}

// DfcExecutionConfig holds configuration for the execution environment.
type DfcExecutionConfig struct {
	Shell   string
	Timeout int
	EnvVars map[string]string
}

func DfcNewExecutionConfig() *DfcExecutionConfig {
	return &DfcExecutionConfig{
		Shell:   "/bin/bash",
		Timeout: 30,
		EnvVars: make(map[string]string),
	}
}

func (ec *DfcExecutionConfig) GetPrefix() string {
	// Step 27: returns the shell path used as command prefix
	prefix := ec.Shell
	return prefix
}

func (ec *DfcExecutionConfig) SetTimeout(seconds int) {
	ec.Timeout = seconds
}

// DfcCommandRunner actually runs shell commands (contains the SINK).
type DfcCommandRunner struct {
	LastExitCode int
	LastOutput   string
}

func DfcNewCommandRunner() *DfcCommandRunner {
	return &DfcCommandRunner{
		LastExitCode: 0,
		LastOutput:   "",
	}
}

func (cr *DfcCommandRunner) Execute(commandString string) string {
	// Step 32: log the command
	logEntry := "Executing: " + commandString
	fmt.Println(logEntry)
	// Step 33: format for execution
	formatted := strings.TrimSpace(commandString)
	// Step 34: split into program and arguments
	parts := strings.Fields(formatted)
	if len(parts) == 0 {
		return "error: empty command"
	}
	program := parts[0]
	args := parts[1:]
	// Step 35: SINK -- tainted data reaches exec.Command
	cmd := exec.Command(program, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		cr.LastExitCode = 1
		cr.LastOutput = "error: " + err.Error()
		return cr.LastOutput
	}
	cr.LastExitCode = 0
	cr.LastOutput = string(output)
	return cr.LastOutput
}
