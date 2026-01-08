package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func (s *DatabaseMCP) toolListFunctions() (mcp.Tool, server.ToolHandlerFunc) {
	return mcp.Tool{
		Name:        "list_functions",
		Description: "List database functions (scalar, table-valued) with pagination",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"schema": map[string]interface{}{
					"type":        "string",
					"description": "Schema name (optional)",
				},
				"type": map[string]interface{}{
					"type":        "string",
					"description": "Function type: 'scalar', 'table' or 'all' (default: all)",
				},
				"name_filter": map[string]interface{}{
					"type":        "string",
					"description": "Filter by function name (uses ILIKE, optional)",
				},
				"page": map[string]interface{}{
					"type":        "number",
					"description": "Page number (default: 1)",
				},
				"page_size": map[string]interface{}{
					"type":        "number",
					"description": "Items per page (default: 100, maximum: 500)",
				},
			},
		},
	}, s.handleListFunctions
}

func (s *DatabaseMCP) handleListFunctions(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, ok := getArgs(request.Params.Arguments)
	if !ok {
		return mcp.NewToolResultError("Invalid arguments"), nil
	}

	schema, err := getValidSchema(args, "")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	funcType, _ := getStringArg(args, "type")
	if funcType == "" {
		funcType = "all"
	}

	// Name filter (optional)
	nameFilter, _ := getStringArg(args, "name_filter")

	// Pagination parameters
	pagination := GetPaginationParams(args, DefaultPageSize, MaxPageSize)

	// Validate function type
	switch funcType {
	case "scalar", "table", "all":
		// valid
	default:
		return mcp.NewToolResultError("Invalid function type. Use: scalar, table, or all"), nil
	}

	// Use query builder to generate database-specific query
	query, queryArgs := s.queryBuilder.ListFunctionsQuery(schema, nameFilter, funcType, pagination.PageSize, pagination.Offset)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Execute query with pagination
	rows, err := s.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error listing functions: %v", err)), nil
	}
	defer rows.Close()

	var functions []map[string]interface{}
	for rows.Next() {
		var routineSchema, routineName, functionType string
		var created, lastAltered time.Time

		if err = rows.Scan(&routineSchema, &routineName, &functionType, &created, &lastAltered); err != nil {
			continue
		}

		fn := map[string]interface{}{
			"schema":       routineSchema,
			"name":         routineName,
			"type":         functionType,
			"created":      created.Format("2006-01-02 15:04:05"),
			"last_altered": lastAltered.Format("2006-01-02 15:04:05"),
		}
		functions = append(functions, fn)
	}

	// Response with pagination metadata
	response := map[string]interface{}{
		"functions": functions,
		"pagination": map[string]interface{}{
			"page":         pagination.Page,
			"page_size":    pagination.PageSize,
			"has_previous": pagination.Page > 1,
		},
		"filter": map[string]interface{}{
			"schema":      schema,
			"type":        funcType,
			"name_filter": nameFilter,
		},
	}

	jsonData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error serializing JSON: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

func (s *DatabaseMCP) toolGetFunctionCode() (mcp.Tool, server.ToolHandlerFunc) {
	return mcp.Tool{
		Name:        "get_function_code",
		Description: "Returns the full source code of a function",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"function_name": map[string]interface{}{
					"type":        "string",
					"description": "Function name",
				},
				"schema": map[string]interface{}{
					"type":        "string",
					"description": "Schema name (optional, default: d",
				},
			},
			Required: []string{"function_name"},
		},
	}, s.handleGetFunctionCode
}

func (s *DatabaseMCP) handleGetFunctionCode(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return mcp.NewToolResultError("Invalid arguments"), nil
	}
	functionName, ok := getStringArg(args, "function_name")
	if !ok || !isValidIdentifier(functionName) {
		return mcp.NewToolResultError("Invalid function name"), nil
	}

	schema, err := getValidSchema(args, "dbo")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Use query builder to generate database-specific query
	query, queryArgs := s.queryBuilder.GetFunctionCodeQuery(schema, functionName)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var definition sql.NullString
	err = s.db.QueryRowContext(ctx, query, queryArgs...).Scan(&definition)
	if err == sql.ErrNoRows {
		return mcp.NewToolResultError("Function not found"), nil
	}
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error fetching function code: %v", err)), nil
	}

	if !definition.Valid || definition.String == "" {
		return mcp.NewToolResultError("Function code not available"), nil
	}

	return mcp.NewToolResultText(definition.String), nil
}
