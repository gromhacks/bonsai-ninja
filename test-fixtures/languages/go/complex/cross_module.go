package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
)

// ---------------------------------------------------------------------------
// cross_module.go -- Cross-file chains calling functions from all 5 existing
// Go example files: handlers.go, services.go, middleware.go, provisioner.go,
// and repository.go.
//
// All chains start from HTTP sources and flow through multiple files before
// reaching a sink. Same package (main), so direct function calls are used.
// ---------------------------------------------------------------------------

// CrossModuleHandler ties together services from all existing files.
type CrossModuleHandler struct {
	repo        *ResourceRepo
	service     *ResourceService
	provisioner *Provisioner
	configMgr   *ConfigManager
	healthCheck *HealthChecker
}

func NewCrossModuleHandler(db *sql.DB) *CrossModuleHandler {
	repo := NewResourceRepo(db)
	svc := NewResourceService(repo)
	prov := NewProvisioner()
	cm := NewConfigManager()
	return &CrossModuleHandler{
		repo:        repo,
		service:     svc,
		provisioner: prov,
		configMgr:   cm,
		healthCheck: nil,
	}
}

// ---------------------------------------------------------------------------
// CHAIN A -- Deep interprocedural: 10+ hops across 4 files
//
// Full chain (12 hops):
//   cross_module.go: ChainA_DeepFlow
//     1. r.FormValue("filter")                          -- source
//     2. parseSearchParams(filter, sortBy, limit)        -- handlers.go
//   handlers.go: parseSearchParams
//     3. returns &SearchParams{Filter: filter, ...}
//   cross_module.go: ChainA_DeepFlow (continued)
//     4. h.service.Search(params)
//   services.go: Search
//     5. buildQuery(params)
//   services.go: buildQuery
//     6. "name LIKE '%" + params.Filter + "%'"           -- string concat
//     7. returns tainted query string
//   services.go: Search (continued)
//     8. NewQueryFilter(query)
//     9. filter.Apply(params)
//     10. h.repo.FindByFilter(filter)
//   repository.go: FindByFilter
//     11. filter.Build()                                  -- services.go
//     12. r.db.Query(sqlQuery)                            -- SINK: SQL injection
//
// This reuses the same deep chain from the original files but enters through
// a new handler that adds an extra decoration step.
// ---------------------------------------------------------------------------

func (h *CrossModuleHandler) ChainA_DeepFlow(w http.ResponseWriter, r *http.Request) {
	filter := r.FormValue("filter")
	sortBy := r.FormValue("sort")
	limit := r.FormValue("limit")

	// Hop 1: call parseSearchParams from handlers.go
	params := parseSearchParams(filter, sortBy, limit)

	// Hop 2: decorate with config (stays tainted)
	prefix := h.configMgr.Get("search.prefix")
	if prefix != nil {
		params.Filter = fmt.Sprintf("%v", prefix) + params.Filter
	}

	// Hop 3-12: service.Search -> buildQuery -> NewQueryFilter -> repo.FindByFilter -> db.Query
	results, err := h.service.Search(params)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(results)
}

// ---------------------------------------------------------------------------
// CHAIN B -- Package-level variable
//
// Full chain:
//   1. r.URL.Query().Get("config") -- source in ChainB_PackageVar
//   2. stored into package-level globalConfigData
//   3. ChainB_ConsumeConfig reads globalConfigData
//   4. h.repo.CustomQuery(clause)   -- repository.go
//   5. "SELECT * FROM resources WHERE " + whereClause -- SINK: SQL injection
//
// The package-level variable bridges two separate handler functions.
// ---------------------------------------------------------------------------

var globalConfigData string

func (h *CrossModuleHandler) ChainB_PackageVar(w http.ResponseWriter, r *http.Request) {
	// Source: user-controlled config data stored in package variable
	globalConfigData = r.URL.Query().Get("config")
	fmt.Fprintf(w, "config stored")
}

func (h *CrossModuleHandler) ChainB_ConsumeConfig(w http.ResponseWriter, r *http.Request) {
	// Read from package variable -- still tainted
	clause := "category = '" + globalConfigData + "'"
	// Sink via repository.go: CustomQuery -> db.Query
	results, err := h.repo.CustomQuery(clause)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(results)
}

// ---------------------------------------------------------------------------
// CHAIN C -- Callback / function parameter
//
// Full chain:
//   1. r.FormValue("region")                            -- source
//   2. applyTransform(region, transformRegion)           -- passes callback
//   3. transformRegion(input) returns tainted string
//   4. h.provisioner.Provision(type, transformed, name)  -- provisioner.go
//   5. NewProvisionConfig(type, region, name)             -- provisioner.go
//   6. config.BuildCommand()                              -- provisioner.go
//   7. "provision-tool --type " + type + " --region " + region + ...
//   8. p.executeProvision(cmdStr)                         -- provisioner.go
//   9. exec.Command("sh", "-c", cmdStr)                   -- SINK: cmd injection
//
// Taint flows through a function passed as a parameter (callback pattern).
// ---------------------------------------------------------------------------

func (h *CrossModuleHandler) ChainC_Callback(w http.ResponseWriter, r *http.Request) {
	region := r.FormValue("region")
	resType := r.FormValue("type")
	name := r.FormValue("name")

	// Pass a transform function as callback -- taint must flow through
	transformed := applyTransform(region, transformRegion)

	// Sink via provisioner.go: Provision -> BuildCommand -> executeProvision -> exec.Command
	result, err := h.provisioner.Provision(resType, transformed, name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(result)
}

func applyTransform(input string, fn func(string) string) string {
	return fn(input)
}

func transformRegion(input string) string {
	// No sanitization -- returns tainted input with a prefix
	return "region-" + input
}

// ---------------------------------------------------------------------------
// CHAIN D -- Re-exported wrapper
//
// Full chain:
//   1. r.URL.Query().Get("endpoint")                      -- source
//   2. wrapHealthCheck(endpoint)                           -- local wrapper
//   3. hc.CheckEndpoint(url)                               -- provisioner.go
//   4. http.Get(url)                                       -- SINK: SSRF
//
// AND:
//   5. r.FormValue("user")                                -- source
//   6. wrapAuditLog(user, action)                          -- local wrapper
//   7. fmt.Printf("AUDIT: user=%s action=%s\n", user, a)  -- similar to handlers.go
//   8. exec.Command("logger", "-t", "audit", msg)          -- SINK: cmd injection
//
// The wrapper functions re-export functionality from other files, adding a
// thin layer that taint must propagate through.
// ---------------------------------------------------------------------------

func (h *CrossModuleHandler) ChainD_ReexportedWrapper(w http.ResponseWriter, r *http.Request) {
	endpoint := r.URL.Query().Get("endpoint")
	user := r.FormValue("user")
	action := r.FormValue("action")

	// Wrapper around HealthChecker.CheckEndpoint from provisioner.go
	if h.healthCheck != nil {
		status := wrapHealthCheck(h.healthCheck, endpoint)
		fmt.Fprintf(w, "health: %s\n", status)
	}

	// Wrapper around audit logging -- re-exports with exec
	wrapAuditLog(user, action)
	fmt.Fprintf(w, "audited %s %s", user, action)
}

func wrapHealthCheck(hc *HealthChecker, endpoint string) string {
	// Thin wrapper that passes taint through to provisioner.go CheckEndpoint
	status, err := hc.CheckEndpoint(endpoint)
	if err != nil {
		return "error"
	}
	return status
}

func wrapAuditLog(user, action string) {
	msg := fmt.Sprintf("user=%s action=%s", user, action)
	// SINK: command injection via logger command
	cmd := exec.Command("logger", "-t", "audit", msg)
	cmd.Run()
}

// ---------------------------------------------------------------------------
// CHAIN E -- Recursive chain
//
// Full chain:
//   1. r.URL.Query().Get("expr")                          -- source
//   2. expandExpression(expr, depth=0)                     -- recursive
//   3. expandExpression calls itself with modified expr
//   4. base case returns accumulated tainted string
//   5. h.repo.CustomQuery(expanded)                        -- repository.go
//   6. "SELECT * FROM resources WHERE " + whereClause      -- SINK: SQL injection
//
// Taint must survive recursive function calls. Each level of recursion
// appends to the tainted string without sanitizing.
// ---------------------------------------------------------------------------

func (h *CrossModuleHandler) ChainE_Recursive(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("expr")
	expanded := expandExpression(expr, 0)
	// Sink via repository.go: CustomQuery -> db.Query
	results, err := h.repo.CustomQuery(expanded)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(results)
}

func expandExpression(expr string, depth int) string {
	if depth >= 3 {
		return expr
	}
	// Each recursion level wraps the expression -- taint survives
	wrapped := "(" + expr + ")"
	return expandExpression(wrapped, depth+1)
}

// ---------------------------------------------------------------------------
// CHAIN F -- Cross-file struct field via middleware token
//
// Full chain:
//   1. r.Header.Get("X-Custom-Query")                     -- source
//   2. generateToken(query)                                -- middleware.go
//   3. validateToken(token)                                -- middleware.go
//   4. extractPayload(token) retrieves the tainted part
//   5. h.repo.CustomQuery(payload)                         -- repository.go
//   6. "SELECT * FROM resources WHERE " + whereClause      -- SINK: SQL injection
//
// Taint flows through the token generation from middleware.go. The payload
// portion of the token preserves the original tainted input.
// ---------------------------------------------------------------------------

func (h *CrossModuleHandler) ChainF_MiddlewareToken(w http.ResponseWriter, r *http.Request) {
	query := r.Header.Get("X-Custom-Query")

	// Use generateToken from middleware.go -- payload is the tainted query
	token := generateToken(query)

	// Extract the payload back (it is the part before the dot)
	payload := extractPayload(token)

	// Sink via repository.go
	results, err := h.repo.CustomQuery(payload)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(results)
}

func extractPayload(token string) string {
	// Token format from middleware.go: payload.signature
	parts := splitOnDot(token)
	if len(parts) >= 1 {
		return parts[0]
	}
	return ""
}

func splitOnDot(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == '.' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// ---------------------------------------------------------------------------
// CHAIN G -- Service + provisioner combined chain
//
// Full chain:
//   1. json.NewDecoder(r.Body).Decode(&req)               -- source
//   2. h.service.Create(name, type, region)                -- services.go
//   3. h.repo.Create(resource)                             -- repository.go (safe)
//   4. req.Command passed to h.provisioner.Provision       -- provisioner.go
//   5. NewProvisionConfig -> BuildCommand -> executeProvision
//   6. exec.Command("sh", "-c", cmdStr)                    -- SINK: cmd injection
//
// This chain combines the service layer (for the resource) with the
// provisioner (for the command), showing taint flowing through both paths.
// ---------------------------------------------------------------------------

func (h *CrossModuleHandler) ChainG_CombinedServiceProvisioner(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Type   string `json:"type"`
		Region string `json:"region"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	// Path 1: create resource through services.go -> repository.go (parameterized, safe)
	_, err := h.service.Create(req.Name, req.Type, req.Region)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Path 2: provision through provisioner.go (tainted command injection)
	result, err := h.provisioner.Provision(req.Type, req.Region, req.Name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(result)
}
