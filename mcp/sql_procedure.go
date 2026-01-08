package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func (s *DatabaseMCP) toolListProcedures() (mcp.Tool, server.ToolHandlerFunc) {
	return mcp.Tool{
		Name:        "list_procedures",
		Description: "List database stored procedures with pagination",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"schema": map[string]interface{}{
					"type":        "string",
					"description": "Schema name (optional)",
				},
				"name_filter": map[string]interface{}{
					"type":        "string",
					"description": "Filter by procedure name (uses ILIKE, optional)",
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
	}, s.handleListProcedures
}

func (s *DatabaseMCP) handleListProcedures(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, ok := getArgs(request.Params.Arguments)
	if !ok {
		return mcp.NewToolResultError("Invalid arguments"), nil
	}

	schema, err := getValidSchema(args, "")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Name filter (optional)
	nameFilter, _ := getStringArg(args, "name_filter")

	// Pagination parameters
	pagination := GetPaginationParams(args, DefaultPageSize, MaxPageSize)

	// Use query builder to generate database-specific query
	query, queryArgs := s.queryBuilder.ListProceduresQuery(schema, nameFilter, pagination.PageSize, pagination.Offset)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Execute query with pagination
	rows, err := s.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error listing procedures: %v", err)), nil
	}
	defer rows.Close()

	var procedures []map[string]interface{}
	for rows.Next() {
		var routineSchema, routineName string
		var created, lastAltered time.Time

		if err = rows.Scan(&routineSchema, &routineName, &created, &lastAltered); err != nil {
			continue
		}

		proc := map[string]interface{}{
			"schema":       routineSchema,
			"name":         routineName,
			"created":      created.Format("2006-01-02 15:04:05"),
			"last_altered": lastAltered.Format("2006-01-02 15:04:05"),
		}
		procedures = append(procedures, proc)
	}

	// Response with pagination metadata
	response := map[string]interface{}{
		"procedures": procedures,
		"pagination": map[string]interface{}{
			"page":         pagination.Page,
			"page_size":    pagination.PageSize,
			"has_previous": pagination.Page > 1,
		},
		"filter": map[string]interface{}{
			"schema":      schema,
			"name_filter": nameFilter,
		},
	}

	jsonData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error serializing JSON: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

func (s *DatabaseMCP) toolGetProcedureCode() (mcp.Tool, server.ToolHandlerFunc) {
	return mcp.Tool{
		Name:        "get_procedure_code",
		Description: "Returns the full source code of a stored procedure",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"procedure_name": map[string]interface{}{
					"type":        "string",
					"description": "Stored procedure name",
				},
				"schema": map[string]interface{}{
					"type":        "string",
					"description": "Schema name (optional, default: dbo)",
				},
			},
			Required: []string{"procedure_name"},
		},
	}, s.handleGetProcedureCode
}

func (s *DatabaseMCP) handleGetProcedureCode(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Invalid arguments"), nil
	}
	procedureName, ok := getStringArg(args, "procedure_name")
	if !ok || !isValidIdentifier(procedureName) {
		return mcp.NewToolResultError("Invalid procedure name"), nil
	}

	schema, err := getValidSchema(args, "dbo")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Use query builder to generate database-specific query
	query, queryArgs := s.queryBuilder.GetProcedureCodeQuery(schema, procedureName)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var definition sql.NullString
	err = s.db.QueryRowContext(ctx, query, queryArgs...).Scan(&definition)
	if err == sql.ErrNoRows {
		return mcp.NewToolResultError("Procedure not found"), nil
	}
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error fetching procedure code: %v", err)), nil
	}

	if !definition.Valid || definition.String == "" {
		return mcp.NewToolResultError("Procedure code not available"), nil
	}

	return mcp.NewToolResultText(definition.String), nil
}

func (s *DatabaseMCP) toolExecuteProcedure() (mcp.Tool, server.ToolHandlerFunc) {
	return mcp.Tool{
		Name:        "execute_procedure",
		Description: "Execute a stored procedure with parameters",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"procedure_name": map[string]interface{}{
					"type":        "string",
					"description": "Stored procedure name",
				},
				"parameters": map[string]interface{}{
					"type":        "object",
					"description": "Procedure parameters as a JSON object",
				},
				"schema": map[string]interface{}{
					"type":        "string",
					"description": "Schema name (optional, default: dbo)",
				},
			},
			Required: []string{"procedure_name"},
		},
	}, s.handleExecuteProcedure
}

func (s *DatabaseMCP) handleExecuteProcedure(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Invalid arguments"), nil
	}
	procedureName, ok := getStringArg(args, "procedure_name")
	if !ok || !isValidIdentifier(procedureName) {
		return mcp.NewToolResultError("Invalid procedure name"), nil
	}

	schema, err := getValidSchema(args, "dbo")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Get stored procedure parameters
	paramsQuery := `
		SELECT 
			p.name,
			TYPE_NAME(p.user_type_id) AS type_name,
			p.is_output
		FROM sys.parameters p
		INNER JOIN sys.objects o ON p.object_id = o.object_id
		INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
		WHERE o.name = @p1 AND s.name = @p2
		ORDER BY p.parameter_id
	`

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, paramsQuery, procedureName, schema)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error fetching parameters: %v", err)), nil
	}

	type paramInfo struct {
		name     string
		typeName string
		isOutput bool
	}
	var procParams []paramInfo

	for rows.Next() {
		var pi paramInfo
		if err = rows.Scan(&pi.name, &pi.typeName, &pi.isOutput); err != nil {
			rows.Close()
			return mcp.NewToolResultError(fmt.Sprintf("Error reading parameters: %v", err)), nil
		}
		procParams = append(procParams, pi)
	}
	rows.Close()

	// Building a secure call using named parameters.
	userParams := make(map[string]interface{})
	if p, ok := args["parameters"].(map[string]interface{}); ok {
		userParams = p
	}

	var paramPlaceholders []string
	var paramValues []interface{}

	for _, pi := range procParams {
		paramName := strings.TrimPrefix(pi.name, "@")
		if val, exists := userParams[paramName]; exists {
			paramPlaceholders = append(paramPlaceholders, fmt.Sprintf("%s = @p%d", pi.name, len(paramValues)+1))
			paramValues = append(paramValues, val)
		} else if !pi.isOutput {
			// Required parameter not provided.
			return mcp.NewToolResultError(fmt.Sprintf("Required parameter not provided: %s", paramName)), nil
		}
	}

	fullName := fmt.Sprintf("[%s].[%s]", schema, procedureName)
	execSQL := fmt.Sprintf("EXEC %s", fullName)
	if len(paramPlaceholders) > 0 {
		execSQL += " " + strings.Join(paramPlaceholders, ", ")
	}

	resultRows, err := s.db.QueryContext(ctx, execSQL, paramValues...)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error executing procedure: %v", err)), nil
	}
	defer resultRows.Close()

	columns, err := resultRows.Columns()
	if err != nil {
		return mcp.NewToolResultText("Procedure executed successfully (no results)"), nil
	}

	var results []map[string]interface{}
	for resultRows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err = resultRows.Scan(valuePtrs...); err != nil {
			continue
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		results = append(results, row)
	}

	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error serializing JSON: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}
