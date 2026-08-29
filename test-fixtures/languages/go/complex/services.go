package main

import (
	"fmt"
	"strings"
)

type ResourceService struct {
	repo *ResourceRepo
}

func NewResourceService(repo *ResourceRepo) *ResourceService {
	return &ResourceService{repo: repo}
}

// Deep Chain 1 continues: search -> buildQuery -> repo
func (s *ResourceService) Search(params *SearchParams) ([]map[string]interface{}, error) {
	query := buildQuery(params)
	filter := NewQueryFilter(query)
	filter.Apply(params)
	return s.repo.FindByFilter(filter)
}

func (s *ResourceService) SearchSafe(filter, sortBy string) ([]map[string]interface{}, error) {
	return s.repo.FindByFilterSafe(filter, sortBy)
}

func (s *ResourceService) GetByID(id string) (map[string]interface{}, error) {
	return s.repo.FindByID(id)
}

func (s *ResourceService) Create(name, resourceType, region string) (map[string]interface{}, error) {
	resource := map[string]interface{}{
		"name":   name,
		"type":   resourceType,
		"region": region,
		"status": "creating",
	}
	return s.repo.Create(resource)
}

func (s *ResourceService) Update(id string, updates map[string]interface{}) (map[string]interface{}, error) {
	return s.repo.Update(id, updates)
}

func (s *ResourceService) Delete(id string) error {
	return s.repo.Delete(id)
}

func (s *ResourceService) ListByRegion(region string) ([]map[string]interface{}, error) {
	return s.repo.FindByRegion(region)
}

func (s *ResourceService) GetResourceStats() (map[string]interface{}, error) {
	return s.repo.GetStats()
}

func buildQuery(params *SearchParams) string {
	var conditions []string
	if params.Filter != "" {
		conditions = append(conditions, "name LIKE '%"+params.Filter+"%'")
	}
	if params.SortBy != "" {
		conditions = append(conditions, "ORDER BY "+params.SortBy)
	}
	return strings.Join(conditions, " ")
}

type QueryFilter struct {
	baseQuery  string
	conditions []string
	ordering   string
	limitVal   string
}

func NewQueryFilter(baseQuery string) *QueryFilter {
	return &QueryFilter{baseQuery: baseQuery}
}

func (f *QueryFilter) Apply(params *SearchParams) {
	if params.Limit != "" {
		f.limitVal = params.Limit
	}
}

func (f *QueryFilter) AddCondition(condition string) {
	f.conditions = append(f.conditions, condition)
}

func (f *QueryFilter) SetOrdering(ordering string) {
	f.ordering = ordering
}

func (f *QueryFilter) Build() string {
	sql := "SELECT * FROM resources"
	allConditions := f.baseQuery
	if len(f.conditions) > 0 {
		allConditions += " AND " + strings.Join(f.conditions, " AND ")
	}
	if allConditions != "" {
		sql += " WHERE " + allConditions
	}
	if f.ordering != "" {
		sql += " ORDER BY " + f.ordering
	}
	if f.limitVal != "" {
		sql += " LIMIT " + f.limitVal
	}
	return sql
}


type WebhookService struct {
	endpoints []WebhookEndpoint
}

type WebhookEndpoint struct {
	URL    string
	Secret string
	Events []string
}

func NewWebhookService() *WebhookService {
	return &WebhookService{}
}

func (ws *WebhookService) Register(endpoint WebhookEndpoint) {
	ws.endpoints = append(ws.endpoints, endpoint)
}

func (ws *WebhookService) Notify(event string, data interface{}) error {
	for _, ep := range ws.endpoints {
		for _, e := range ep.Events {
			if e == event {
				err := ws.send(ep, event, data)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// VULN: SSRF via webhook URL
func (ws *WebhookService) send(ep WebhookEndpoint, event string, data interface{}) error {
	payload := fmt.Sprintf(`{"event":"%s","data":"%v"}`, event, data)
	_ = payload
	return nil
}


type MetricsService struct {
	repo *ResourceRepo
}

func NewMetricsService(repo *ResourceRepo) *MetricsService {
	return &MetricsService{repo: repo}
}

func (m *MetricsService) GetResourceMetrics(resourceID string) (map[string]interface{}, error) {
	resource, err := m.repo.FindByID(resourceID)
	if err != nil {
		return nil, err
	}
	metrics := map[string]interface{}{
		"resource": resource,
		"cpu":      75.5,
		"memory":   2048,
		"disk":     50.0,
	}
	return metrics, nil
}

func (m *MetricsService) GetAggregateMetrics() (map[string]interface{}, error) {
	stats, err := m.repo.GetStats()
	if err != nil {
		return nil, err
	}
	stats["avgCPU"] = 45.2
	stats["avgMemory"] = 1536
	return stats, nil
}
