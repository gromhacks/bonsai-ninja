package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

type ResourceHandler struct {
	service    *ResourceService
	provisioner *Provisioner
}

func NewResourceHandler(db *sql.DB) *ResourceHandler {
	repo := NewResourceRepo(db)
	svc := NewResourceService(repo)
	prov := NewProvisioner()
	return &ResourceHandler{service: svc, provisioner: prov}
}

// Deep Chain 1 entry: SQL injection
func (h *ResourceHandler) SearchResources(w http.ResponseWriter, r *http.Request) {
	filter := r.FormValue("filter")
	sortBy := r.FormValue("sort")
	limit := r.FormValue("limit")
	params := parseSearchParams(filter, sortBy, limit)
	results, err := h.service.Search(params)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(results)
}

func (h *ResourceHandler) SearchResourcesSafe(w http.ResponseWriter, r *http.Request) {
	filter := r.FormValue("filter")
	sortBy := r.FormValue("sort")
	results, err := h.service.SearchSafe(filter, sortBy)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(results)
}

func (h *ResourceHandler) GetResource(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	resource, err := h.service.GetByID(id)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	json.NewEncoder(w).Encode(resource)
}

func (h *ResourceHandler) CreateResource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Type   string `json:"type"`
		Region string `json:"region"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	resource, err := h.service.Create(req.Name, req.Type, req.Region)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(resource)
}

// VULN: Command injection - Deep Chain 2
func (h *ResourceHandler) ProvisionResource(w http.ResponseWriter, r *http.Request) {
	resourceType := r.FormValue("type")
	region := r.FormValue("region")
	name := r.FormValue("name")
	result, err := h.provisioner.Provision(resourceType, region, name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(result)
}

func (h *ResourceHandler) ProvisionResourceSafe(w http.ResponseWriter, r *http.Request) {
	resourceType := r.FormValue("type")
	region := r.FormValue("region")
	name := r.FormValue("name")
	result, err := h.provisioner.ProvisionSafe(resourceType, region, name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(result)
}

// VULN: XSS via template
func (h *ResourceHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	// Unsafe: directly injecting user input
	tmplStr := "<html><body><h1>Dashboard</h1><p>Search: " + search + "</p></body></html>"
	tmpl := template.Must(template.New("dash").Parse(tmplStr))
	tmpl.Execute(w, nil)
}

func (h *ResourceHandler) DashboardSafe(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	escaped := html.EscapeString(search)
	tmplStr := "<html><body><h1>Dashboard</h1><p>Search: " + escaped + "</p></body></html>"
	tmpl := template.Must(template.New("dash").Parse(tmplStr))
	tmpl.Execute(w, nil)
}

// VULN: Path traversal
func (h *ResourceHandler) DownloadLog(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	logPath := filepath.Join("/var/log/gateway", filename)
	data, err := os.ReadFile(logPath)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	w.Write(data)
}

func (h *ResourceHandler) DownloadLogSafe(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.URL.Query().Get("file"))
	logPath := filepath.Join("/var/log/gateway", filename)
	absPath, _ := filepath.Abs(logPath)
	baseDir, _ := filepath.Abs("/var/log/gateway")
	if len(absPath) < len(baseDir) || absPath[:len(baseDir)] != baseDir {
		http.Error(w, "Invalid path", 400)
		return
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	w.Write(data)
}

// VULN: SSRF
func (h *ResourceHandler) ProxyRequest(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

// VULN: SSRF safe
func (h *ResourceHandler) ProxyRequestSafe(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if !isAllowedURL(targetURL) {
		http.Error(w, "URL not allowed", 400)
		return
	}
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

// VULN: Template injection
func (h *ResourceHandler) RenderNotification(w http.ResponseWriter, r *http.Request) {
	message := r.FormValue("message")
	tmpl := template.Must(template.New("notif").Parse(message))
	tmpl.Execute(w, nil)
}

// VULN: Log injection
func (h *ResourceHandler) AuditLog(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("action")
	user := r.FormValue("user")
	fmt.Printf("AUDIT: user=%s action=%s\n", user, action)
	w.Write([]byte("Logged"))
}

// VULN: Command injection via exec
func (h *ResourceHandler) SystemInfo(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(output)
}

// VULN: Deserialization via JSON decode to interface
func (h *ResourceHandler) ImportConfig(w http.ResponseWriter, r *http.Request) {
	var config interface{}
	json.NewDecoder(r.Body).Decode(&config)
	fmt.Fprintf(w, "Imported: %v", config)
}

func parseSearchParams(filter, sortBy, limit string) *SearchParams {
	return &SearchParams{
		Filter: filter,
		SortBy: sortBy,
		Limit:  limit,
	}
}

type SearchParams struct {
	Filter string
	SortBy string
	Limit  string
}

func isAllowedURL(url string) bool {
	blocked := []string{"localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254"}
	for _, b := range blocked {
		if contains(url, b) {
			return false
		}
	}
	return true
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
