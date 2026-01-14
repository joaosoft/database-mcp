package mcp

import "fmt"

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

// isValidIdentifier validates SQL identifiers to prevent SQL injection
func isValidIdentifier(name string) bool {
	if name == "" || len(name) >= 128 {
		return false
	}
	// Allow bracketed identifiers [name] - SQL Server style escaping
	if len(name) >= 2 && name[0] == '[' && name[len(name)-1] == ']' {
		// Extract name inside brackets and validate it allows more chars
		innerName := name[1 : len(name)-1]
		return len(innerName) > 0 && reValidIdentifierBracketed.MatchString(innerName)
	}
	return reValidIdentifier.MatchString(name)
}

// getValidSchema sanitizes and validates schema name
func getValidSchema(args map[string]interface{}, defaultSchema string) (string, error) {
	schema := defaultSchema
	if sc, ok := args["schema"].(string); ok && sc != "" {
		schema = sc
	}
	if schema != "" && !isValidIdentifier(schema) {
		return "", fmt.Errorf("%w: %s", ErrInvalidIdentifier, schema)
	}
	return schema, nil
}

// getStringArg safely extracts a string argument
func getStringArg(args map[string]interface{}, key string) (string, bool) {
	val, ok := args[key].(string)
	return val, ok
}

// getIntArg safely extracts an integer argument with default value
func getIntArg(args map[string]interface{}, key string, defaultVal int) int {
	if val, ok := args[key].(float64); ok {
		return int(val)
	}
	return defaultVal
}

// getBoolArg safely extracts a boolean argument with default value
func getBoolArg(args map[string]interface{}, key string, defaultVal bool) bool {
	if val, ok := args[key].(bool); ok {
		return val
	}
	return defaultVal
}

// getArgs safely extracts arguments map from request
func getArgs(arguments interface{}) (map[string]interface{}, bool) {
	args, ok := arguments.(map[string]interface{})
	return args, ok
}

// getDefaultSchema returns the default schema for the given driver
func getDefaultSchema(driver DriverType) string {
	switch driver {
	case DriverSQLServer:
		return DefaultSchemaSQLServer
	case DriverPostgresSQL:
		return DefaultSchemaPostgres
	case DriverMySQL:
		return DefaultSchemaMySQL
	case DriverOracle:
		return DefaultSchemaOracle
	case DriverSQLite:
		return DefaultSchemaSQLite
	default:
		return ""
	}
}
