package main

import (
	"database/sql"
	"fmt"
)

type ResourceRepo struct {
	db *sql.DB
}

func NewResourceRepo(db *sql.DB) *ResourceRepo {
	return &ResourceRepo{db: db}
}

func (r *ResourceRepo) FindByID(id string) (map[string]interface{}, error) {
	row := r.db.QueryRow("SELECT id, name, type, region, status FROM resources WHERE id = ?", id)
	var resID, name, resType, region, status string
	err := row.Scan(&resID, &name, &resType, &region, &status)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"id": resID, "name": name, "type": resType, "region": region, "status": status,
	}, nil
}

// VULN: SQL injection - Deep Chain 1 sink
func (r *ResourceRepo) FindByFilter(filter *QueryFilter) ([]map[string]interface{}, error) {
	sqlQuery := filter.Build()
	rows, err := r.db.Query(sqlQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// Safe version with parameterized query
func (r *ResourceRepo) FindByFilterSafe(filterText, sortBy string) ([]map[string]interface{}, error) {
	allowedSorts := map[string]bool{"name": true, "type": true, "region": true, "created_at": true}
	safeSortBy := "name"
	if allowedSorts[sortBy] {
		safeSortBy = sortBy
	}
	query := fmt.Sprintf("SELECT * FROM resources WHERE name LIKE ? ORDER BY %s", safeSortBy)
	rows, err := r.db.Query(query, "%"+filterText+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func (r *ResourceRepo) Create(data map[string]interface{}) (map[string]interface{}, error) {
	result, err := r.db.Exec(
		"INSERT INTO resources (name, type, region, status) VALUES (?, ?, ?, ?)",
		data["name"], data["type"], data["region"], data["status"],
	)
	if err != nil {
		return nil, err
	}
	id, _ := result.LastInsertId()
	data["id"] = id
	return data, nil
}

func (r *ResourceRepo) Update(id string, updates map[string]interface{}) (map[string]interface{}, error) {
	_, err := r.db.Exec("UPDATE resources SET status = ? WHERE id = ?", updates["status"], id)
	if err != nil {
		return nil, err
	}
	return r.FindByID(id)
}

func (r *ResourceRepo) Delete(id string) error {
	_, err := r.db.Exec("DELETE FROM resources WHERE id = ?", id)
	return err
}

func (r *ResourceRepo) FindByRegion(region string) ([]map[string]interface{}, error) {
	rows, err := r.db.Query("SELECT * FROM resources WHERE region = ?", region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func (r *ResourceRepo) GetStats() (map[string]interface{}, error) {
	var count int
	err := r.db.QueryRow("SELECT COUNT(*) FROM resources").Scan(&count)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"totalResources": count}, nil
}

// VULN: SQL injection in custom query
func (r *ResourceRepo) CustomQuery(whereClause string) ([]map[string]interface{}, error) {
	sqlStr := "SELECT * FROM resources WHERE " + whereClause
	rows, err := r.db.Query(sqlStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func scanRows(rows *sql.Rows) ([]map[string]interface{}, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var results []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		rows.Scan(pointers...)
		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = values[i]
		}
		results = append(results, row)
	}
	return results, nil
}
