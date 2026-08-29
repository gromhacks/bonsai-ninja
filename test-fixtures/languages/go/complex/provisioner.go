package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

type Provisioner struct {
	allowedTypes []string
}

func NewProvisioner() *Provisioner {
	return &Provisioner{
		allowedTypes: []string{"vm", "container", "database", "storage", "network"},
	}
}

// VULN: Command injection - Deep Chain 2
func (p *Provisioner) Provision(resourceType, region, name string) (map[string]interface{}, error) {
	config := NewProvisionConfig(resourceType, region, name)
	config.Validate()
	cmdStr := config.BuildCommand()
	return p.executeProvision(cmdStr)
}

func (p *Provisioner) ProvisionSafe(resourceType, region, name string) (map[string]interface{}, error) {
	allowed := map[string]bool{"vm": true, "container": true, "database": true}
	if !allowed[resourceType] {
		return nil, fmt.Errorf("invalid resource type: %s", resourceType)
	}
	allowedRegions := map[string]bool{"us-east-1": true, "us-west-2": true, "eu-west-1": true}
	if !allowedRegions[region] {
		return nil, fmt.Errorf("invalid region: %s", region)
	}
	cmd := exec.Command("provision-tool", "--type", resourceType, "--region", region, "--name", name)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"status": "provisioned", "output": string(output)}, nil
}

// VULN: Command injection sink
func (p *Provisioner) executeProvision(cmdStr string) (map[string]interface{}, error) {
	cmd := exec.Command("sh", "-c", cmdStr)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"status": "provisioned", "output": string(output)}, nil
}

func (p *Provisioner) Deprovision(resourceID string) error {
	cmd := exec.Command("provision-tool", "delete", "--id", resourceID)
	return cmd.Run()
}

func (p *Provisioner) GetStatus(resourceID string) (string, error) {
	cmd := exec.Command("provision-tool", "status", "--id", resourceID)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}


type ProvisionConfig struct {
	ResourceType string
	Region       string
	Name         string
	Options      map[string]string
}

func NewProvisionConfig(resourceType, region, name string) *ProvisionConfig {
	return &ProvisionConfig{
		ResourceType: resourceType,
		Region:       region,
		Name:         name,
		Options:      make(map[string]string),
	}
}

func (c *ProvisionConfig) Validate() error {
	if c.ResourceType == "" {
		return fmt.Errorf("resource type required")
	}
	if c.Region == "" {
		return fmt.Errorf("region required")
	}
	return nil
}

// VULN: builds command string with user input
func (c *ProvisionConfig) BuildCommand() string {
	cmd := "provision-tool --type " + c.ResourceType + " --region " + c.Region + " --name " + c.Name
	for k, v := range c.Options {
		cmd += " --" + k + " " + v
	}
	return cmd
}

func (c *ProvisionConfig) SetOption(key, value string) {
	c.Options[key] = value
}


type HealthChecker struct {
	endpoints []string
}

func NewHealthChecker(endpoints []string) *HealthChecker {
	return &HealthChecker{endpoints: endpoints}
}

// VULN: SSRF via health check endpoint
func (hc *HealthChecker) CheckAll() (map[string]string, error) {
	results := make(map[string]string)
	for _, endpoint := range hc.endpoints {
		resp, err := http.Get(endpoint)
		if err != nil {
			results[endpoint] = "unhealthy"
			continue
		}
		resp.Body.Close()
		results[endpoint] = "healthy"
	}
	return results, nil
}

func (hc *HealthChecker) CheckEndpoint(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "unhealthy", err
	}
	resp.Body.Close()
	return fmt.Sprintf("status: %d", resp.StatusCode), nil
}


type ConfigManager struct {
	configs map[string]interface{}
}

func NewConfigManager() *ConfigManager {
	return &ConfigManager{configs: make(map[string]interface{})}
}

func (cm *ConfigManager) LoadFromJSON(data string) error {
	return json.Unmarshal([]byte(data), &cm.configs)
}

func (cm *ConfigManager) Get(key string) interface{} {
	parts := strings.Split(key, ".")
	current := cm.configs
	for i, part := range parts {
		val, ok := current[part]
		if !ok {
			return nil
		}
		if i == len(parts)-1 {
			return val
		}
		nested, ok := val.(map[string]interface{})
		if !ok {
			return nil
		}
		current = nested
	}
	return nil
}

func (cm *ConfigManager) Set(key string, value interface{}) {
	cm.configs[key] = value
}
