package mcp

import (
	"fmt"
)

// Pagination defaults and limits
const (
	DefaultPage        = 1
	DefaultPageSize    = 100
	MaxPageSize        = 500
	MaxPageSizeLarge   = 1000
)

// PaginationParams holds pagination parameters
type PaginationParams struct {
	Page     int
	PageSize int
	Offset   int
}

// GetPaginationParams extracts and validates pagination parameters from args
func GetPaginationParams(args map[string]interface{}, defaultPageSize, maxPageSize int) PaginationParams {
	page := DefaultPage
	pageSize := defaultPageSize

	if pageVal, ok := args["page"].(float64); ok {
		page = int(pageVal)
		if page < 1 {
			page = 1
		}
	}

	if pageSizeVal, ok := args["page_size"].(float64); ok {
		pageSize = int(pageSizeVal)
		if pageSize < 1 {
			pageSize = defaultPageSize
		}
		if pageSize > maxPageSize {
			pageSize = maxPageSize
		}
	}

	return PaginationParams{
		Page:     page,
		PageSize: pageSize,
		Offset:   (page - 1) * pageSize,
	}
}

// Validating SQL identifiers to prevent SQL injection.
func isValidIdentifier(name string) bool {
	// It allows letters, numbers, underlining, and some common special characters
	// Uses precompiled regex from sql_query_validation.go
	return reValidIdentifier.MatchString(name) && len(name) > 0 && len(name) < 128
}

// Sanitize and validate schema
func getValidSchema(args map[string]interface{}, defaultSchema string) (string, error) {
	schema := defaultSchema
	if sc, ok := args["schema"].(string); ok && sc != "" {
		schema = sc
	}
	if schema != "" && !isValidIdentifier(schema) {
		return "", fmt.Errorf("invalid schema name: %s", schema)
	}
	return schema, nil
}

// Helper for converting string arguments safely
func getStringArg(args map[string]interface{}, key string) (string, bool) {
	val, ok := args[key].(string)
	return val, ok
}

// Helper for converting integer arguments safely
func getIntArg(args map[string]interface{}, key string, defaultVal int) int {
	if val, ok := args[key].(float64); ok {
		return int(val)
	}
	return defaultVal
}

// getArgs safely extracts arguments map from request
func getArgs(arguments interface{}) (map[string]interface{}, bool) {
	args, ok := arguments.(map[string]interface{})
	return args, ok
}
