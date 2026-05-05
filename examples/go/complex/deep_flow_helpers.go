package main

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// deep_flow_helpers.go -- Middleware classes for deep flow chain.
//
// Contains: DfcRequestContext, DfcMiddlewareChain, DfcCommandRegistry,
//           DfcConfigLoader
// ---------------------------------------------------------------------------

// DfcRequestContext carries command data through the middleware pipeline.
type DfcRequestContext struct {
	Command  string
	Params   string
	Metadata map[string]string
	TraceLog []string
}

func DfcNewRequestContext(command string, params string) *DfcRequestContext {
	// Step 12 (from caller): store command and params
	ctx := &DfcRequestContext{
		Command:  command,
		Params:   params,
		Metadata: make(map[string]string),
		TraceLog: make([]string, 0),
	}
	return ctx
}

func (ctx *DfcRequestContext) AppendTrace(entry string) {
	ctx.TraceLog = append(ctx.TraceLog, entry)
}

func (ctx *DfcRequestContext) GetFullPayload() string {
	payload := ctx.Command + " --args " + ctx.Params
	return payload
}

// DfcMiddlewareChain processes a DfcRequestContext through middleware functions.
type DfcMiddlewareChain struct {
	middlewares []func(*DfcRequestContext) *DfcRequestContext
}

func DfcNewMiddlewareChain() *DfcMiddlewareChain {
	return &DfcMiddlewareChain{
		middlewares: make([]func(*DfcRequestContext) *DfcRequestContext, 0),
	}
}

func (mc *DfcMiddlewareChain) AddLoggingMiddleware() {
	loggingMW := func(ctx *DfcRequestContext) *DfcRequestContext {
		// Step 17: read command from context
		loggedCmd := ctx.Command
		ctx.AppendTrace("LOG: " + loggedCmd)
		return ctx
	}
	mc.middlewares = append(mc.middlewares, loggingMW)
}

func (mc *DfcMiddlewareChain) AddTransformMiddleware() {
	transformMW := func(ctx *DfcRequestContext) *DfcRequestContext {
		// Step 18: read params from context
		rawParams := ctx.Params
		// Step 19: transform params (format for shell)
		transformed := strings.ReplaceAll(rawParams, ",", " ")
		// Step 20: write back to context
		ctx.Params = transformed
		// Step 21: update metadata with transform record
		ctx.Metadata["transformed"] = "true"
		ctx.Metadata["original_params"] = rawParams
		return ctx
	}
	mc.middlewares = append(mc.middlewares, transformMW)
}

func (mc *DfcMiddlewareChain) Process(ctx *DfcRequestContext) *DfcRequestContext {
	// Steps 16-21: each middleware reads and modifies the context
	current := ctx
	for _, mw := range mc.middlewares {
		current = mw(current)
	}
	return current
}

// DfcCommandRegistry is a registry of available plugin command handlers.
type DfcCommandRegistry struct {
	handlers map[string]string
}

func DfcNewCommandRegistry() *DfcCommandRegistry {
	return &DfcCommandRegistry{
		handlers: map[string]string{
			"deploy":  "dfc_deploy_handler",
			"backup":  "dfc_backup_handler",
			"migrate": "dfc_migrate_handler",
			"shell":   "dfc_shell_handler",
		},
	}
}

func (r *DfcCommandRegistry) GetHandler(pluginName string) string {
	// Step 24 (from caller): resolve plugin name to handler
	handler, ok := r.handlers[pluginName]
	if ok {
		return handler
	}
	// Fallback: use the plugin name itself as the handler
	fallback := pluginName + "_handler"
	return fallback
}

func (r *DfcCommandRegistry) ListPlugins() []string {
	keys := make([]string, 0, len(r.handlers))
	for k := range r.handlers {
		keys = append(keys, k)
	}
	return keys
}

// DfcConfigLoader loads configuration that affects command execution.
type DfcConfigLoader struct {
	ConfigPath string
	Settings   map[string]string
}

func DfcNewConfigLoader() *DfcConfigLoader {
	return &DfcConfigLoader{
		ConfigPath: "/etc/plugins.conf",
		Settings:   make(map[string]string),
	}
}

func (cl *DfcConfigLoader) Load() map[string]string {
	cl.Settings["timeout"] = "30"
	cl.Settings["shell"] = "/bin/bash"
	cl.Settings["allow_exec"] = "true"
	return cl.Settings
}

func (cl *DfcConfigLoader) GetShell() string {
	if _, ok := cl.Settings["shell"]; !ok {
		cl.Load()
	}
	shellPath := cl.Settings["shell"]
	_ = fmt.Sprintf("shell: %s", shellPath)
	return shellPath
}
