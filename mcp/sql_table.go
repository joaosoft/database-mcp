package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func (s *DatabaseMCP) toolListTables() (mcp.Tool, server.ToolHandlerFunc) {
	return mcp.Tool{
		Name:        "list_tables",
		Description: "List database tables with pagination",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"schema": map[string]interface{}{
					"type":        "string",
					"description": "Schema name (optional, default: dbo)",
				},
				"name_filter": map[string]interface{}{
					"type":        "string",
					"description": "Filter by table name (uses ILIKE, optional)",
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
	}, s.handleListTables
}

func (s *DatabaseMCP) handleListTables(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
	query, queryArgs := s.queryBuilder.ListTablesQuery(schema, nameFilter, pagination.PageSize, pagination.Offset)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Execute query with pagination
	rows, err := s.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error listing tables: %v", err)), nil
	}
	defer rows.Close()

	var tables []map[string]interface{}
	for rows.Next() {
		var tableSchema, tableName, tableType string
		if err = rows.Scan(&tableSchema, &tableName, &tableType); err != nil {
			continue
		}
		tables = append(tables, map[string]interface{}{
			"schema": tableSchema,
			"name":   tableName,
			"type":   tableType,
		})
	}

	// Response with pagination metadata
	response := map[string]interface{}{
		"tables": tables,
		"pagination": map[string]interface{}{
			"page":      pagination.Page,
			"page_size": pagination.PageSize,
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

func (s *DatabaseMCP) toolDescribeTable() (mcp.Tool, server.ToolHandlerFunc) {
	return mcp.Tool{
		Name:        "describe_table",
		Description: "Returns the structure of a table (columns, types, constraints)",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"table_name": map[string]interface{}{
					"type":        "string",
					"description": "Table name",
				},
				"schema": map[string]interface{}{
					"type":        "string",
					"description": "Schema name (optional, default: dbo)",
				},
			},
			Required: []string{"table_name"},
		},
	}, s.handleDescribeTable
}

func (s *DatabaseMCP) handleDescribeTable(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Invalid arguments"), nil
	}
	tableName, ok := getStringArg(args, "table_name")
	if !ok || !isValidIdentifier(tableName) {
		return mcp.NewToolResultError("Invalid table name"), nil
	}

	schema, err := getValidSchema(args, "dbo")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Use query builder to generate database-specific query
	query, queryArgs := s.queryBuilder.DescribeTableQuery(schema, tableName)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error describing table: %v", err)), nil
	}
	defer rows.Close()

	var columns []map[string]interface{}
	for rows.Next() {
		var colName, dataType, isNullable string
		var maxLength sql.NullInt64
		var colDefault sql.NullString

		if err = rows.Scan(&colName, &dataType, &maxLength, &isNullable, &colDefault); err != nil {
			continue
		}

		col := map[string]interface{}{
			"name":     colName,
			"type":     dataType,
			"nullable": isNullable == "YES",
		}
		if maxLength.Valid {
			col["max_length"] = maxLength.Int64
		}
		if colDefault.Valid {
			col["default"] = colDefault.String
		}
		columns = append(columns, col)
	}

	if len(columns) == 0 {
		return mcp.NewToolResultError("Table not found"), nil
	}

	jsonData, err := json.MarshalIndent(columns, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error serializing JSON: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

func (s *DatabaseMCP) toolListTableRows() (mcp.Tool, server.ToolHandlerFunc) {
	return mcp.Tool{
		Name:        "list_table_rows",
		Description: "List the rows of a database table with pagination and advanced filters",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"table_name": map[string]interface{}{
					"type":        "string",
					"description": "Table name",
				},
				"schema": map[string]interface{}{
					"type":        "string",
					"description": "Schema name (optional, default: dbo)",
				},
				"filters": map[string]interface{}{
					"type":        "array",
					"description": "Filters (e.g.: [{\"column\": \"info\", \"operator\": \"contains\", \"value\": \"or\"}, {\"column\": \"id\", \"operator\": \"eq\", \"value\": 123}])",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"column": map[string]interface{}{
								"type":        "string",
								"description": "Column name",
							},
							"operator": map[string]interface{}{
								"type":        "string",
								"description": "Operador: eq (=), neq (!=), gt (>), gte (>=), lt (<), lte (<=), contains, starts_with, ends_with, is_null, is_not_null",
								"enum":        []string{"eq", "neq", "gt", "gte", "lt", "lte", "contains", "starts_with", "ends_with", "is_null", "is_not_null"},
							},
							"value": map[string]interface{}{
								"description": "Value to compare (not required for is_null/is_not_null)",
							},
						},
						"required": []string{"column", "operator"},
					},
				},
				"page": map[string]interface{}{
					"type":        "number",
					"description": "Page number (default: 1)",
				},
				"page_size": map[string]interface{}{
					"type":        "number",
					"description": "Items per page (default: 50, maximum: 1000)",
				},
				"order_by": map[string]interface{}{
					"type":        "string",
					"description": "Column for sorting (optional)",
				},
				"order_direction": map[string]interface{}{
					"type":        "string",
					"description": "Sorting direction: ASC or DESC (default: ASC)",
				},
			},
			Required: []string{"table_name"},
		},
	}, s.handleListTableRows
}

func (s *DatabaseMCP) handleListTableRows(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Invalid arguments"), nil
	}

	// Validate table_name
	tableName, ok := args["table_name"].(string)
	if !ok || tableName == "" {
		return mcp.NewToolResultError("table_name is required."), nil
	}

	schema, err := getValidSchema(args, "dbo")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Check if the table exists
	tableExistsQuery, tableExistsQueryArgs := s.queryBuilder.TableExistsQuery(schema, tableName)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var tableExists int
	err = s.db.QueryRowContext(ctx, tableExistsQuery, tableExistsQueryArgs...).Scan(&tableExists)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error checking table: %v", err)), nil
	}
	if tableExists == 0 {
		return mcp.NewToolResultError(fmt.Sprintf("Table %s.%s not found", schema, tableName)), nil
	}

	// Pagination parameters
	page := 1
	pageSize := 50

	if pageVal, ok := args["page"].(float64); ok {
		page = int(pageVal)
		if page < 1 {
			page = 1
		}
	}

	if pageSizeVal, ok := args["page_size"].(float64); ok {
		pageSize = int(pageSizeVal)
		if pageSize < 1 {
			pageSize = 50
		}
		if pageSize > 1000 {
			pageSize = 1000
		}
	}

	// Sorting parameters
	orderBy := ""
	if orderByVal, ok := args["order_by"].(string); ok {
		orderBy = orderByVal
	}

	orderDirection := "ASC"
	if orderDirVal, ok := args["order_direction"].(string); ok {
		orderDirVal = strings.ToUpper(orderDirVal)
		if orderDirVal == "DESC" || orderDirVal == "ASC" {
			orderDirection = orderDirVal
		}
	}

	// Get information from the columns
	columnsQuery, columnsQueryArgs := s.queryBuilder.GetTableColumnsQuery(schema, tableName)

	columnsRows, err := s.db.QueryContext(ctx, columnsQuery, columnsQueryArgs...)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error retrieving columns: %v", err)), nil
	}
	defer columnsRows.Close()

	var columns []string
	columnTypes := make(map[string]string)
	var firstColumn string

	for columnsRows.Next() {
		var columnName, dataType string
		var ordinalPosition int
		if err = columnsRows.Scan(&columnName, &dataType, &ordinalPosition); err != nil {
			continue
		}
		columns = append(columns, columnName)
		columnTypes[columnName] = dataType
		if ordinalPosition == 1 {
			firstColumn = columnName
		}
	}

	if len(columns) == 0 {
		return mcp.NewToolResultError("No columns found in the table."), nil
	}

	// Validate orderBy if provided
	if orderBy != "" {
		validColumn := false
		for _, col := range columns {
			if strings.EqualFold(col, orderBy) {
				orderBy = col
				validColumn = true
				break
			}
		}
		if !validColumn {
			return mcp.NewToolResultError(fmt.Sprintf("The sorting column '%s' does not exist in the table", orderBy)), nil
		}
	} else {
		orderBy = firstColumn
	}

	// Process unified filters
	var whereClauses []string
	var queryParams []interface{}
	paramIndex := 1

	if filters, ok := args["filters"].([]interface{}); ok {
		for _, filterInterface := range filters {
			filter, ok := filterInterface.(map[string]interface{})
			if !ok {
				continue
			}

			column, _ := filter["column"].(string)
			operator, _ := filter["operator"].(string)

			if column == "" || operator == "" {
				continue
			}

			// Validate if the column exists
			validColumn := false
			var actualColumn string
			for _, col := range columns {
				if strings.EqualFold(col, column) {
					actualColumn = col
					validColumn = true
					break
				}
			}
			if !validColumn {
				return mcp.NewToolResultError(fmt.Sprintf("The filter column '%s' does not exist in the table", column)), nil
			}

			// Operator-based processing
			switch operator {
			case "eq":
				whereClauses = append(whereClauses, fmt.Sprintf("[%s] = @p%d", actualColumn, paramIndex))
				queryParams = append(queryParams, filter["value"])
				paramIndex++

			case "neq":
				whereClauses = append(whereClauses, fmt.Sprintf("[%s] != @p%d", actualColumn, paramIndex))
				queryParams = append(queryParams, filter["value"])
				paramIndex++

			case "gt":
				whereClauses = append(whereClauses, fmt.Sprintf("[%s] > @p%d", actualColumn, paramIndex))
				queryParams = append(queryParams, filter["value"])
				paramIndex++

			case "gte":
				whereClauses = append(whereClauses, fmt.Sprintf("[%s] >= @p%d", actualColumn, paramIndex))
				queryParams = append(queryParams, filter["value"])
				paramIndex++

			case "lt":
				whereClauses = append(whereClauses, fmt.Sprintf("[%s] < @p%d", actualColumn, paramIndex))
				queryParams = append(queryParams, filter["value"])
				paramIndex++

			case "lte":
				whereClauses = append(whereClauses, fmt.Sprintf("[%s] <= @p%d", actualColumn, paramIndex))
				queryParams = append(queryParams, filter["value"])
				paramIndex++

			case "contains":
				value, ok := filter["value"].(string)
				if !ok {
					return mcp.NewToolResultError(fmt.Sprintf("The 'contains' operator requires a string value.")), nil
				}
				whereClauses = append(whereClauses, fmt.Sprintf("[%s] ILIKE @p%d", actualColumn, paramIndex))
				queryParams = append(queryParams, "%"+value+"%")
				paramIndex++

			case "starts_with":
				value, ok := filter["value"].(string)
				if !ok {
					return mcp.NewToolResultError(fmt.Sprintf("The 'starts_with' operator requires a string value.")), nil
				}
				whereClauses = append(whereClauses, fmt.Sprintf("[%s] ILIKE @p%d", actualColumn, paramIndex))
				queryParams = append(queryParams, value+"%")
				paramIndex++

			case "ends_with":
				value, ok := filter["value"].(string)
				if !ok {
					return mcp.NewToolResultError(fmt.Sprintf("The 'ends_with' operator requires a string value.")), nil
				}
				whereClauses = append(whereClauses, fmt.Sprintf("[%s] ILIKE @p%d", actualColumn, paramIndex))
				queryParams = append(queryParams, "%"+value)
				paramIndex++

			case "is_null":
				whereClauses = append(whereClauses, fmt.Sprintf("[%s] IS NULL", actualColumn))

			case "is_not_null":
				whereClauses = append(whereClauses, fmt.Sprintf("[%s] IS NOT NULL", actualColumn))

			default:
				return mcp.NewToolResultError(fmt.Sprintf("Invalid operator: %s", operator)), nil
			}
		}
	}

	// Assemble final WHERE clause
	whereClause := ""
	if len(whereClauses) > 0 {
		whereClause = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Calculate offset
	offset := (page - 1) * pageSize

	// Query to count total rows
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM [%s].[%s] %s", schema, tableName, whereClause)

	var totalCount int
	err = s.db.QueryRowContext(ctx, countQuery, queryParams...).Scan(&totalCount)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error counting lines: %v", err)), nil
	}

	// Calculate total pages
	totalPages := (totalCount + pageSize - 1) / pageSize
	if totalCount == 0 {
		totalPages = 0
	}

	// Query to retrieve data with pagination
	columnsStr := strings.Join(columns, "], [")
	dataQuery := fmt.Sprintf(`
       SELECT [%s]
       FROM [%s].[%s]
       %s
       ORDER BY [%s] %s
       OFFSET %d ROWS
       FETCH NEXT %d ROWS ONLY
    `, columnsStr, schema, tableName, whereClause, orderBy, orderDirection, offset, pageSize)

	dataRows, err := s.db.QueryContext(ctx, dataQuery, queryParams...)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error retrieving data: %v", err)), nil
	}
	defer dataRows.Close()

	// Process results
	var rows []map[string]interface{}
	for dataRows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err = dataRows.Scan(valuePtrs...); err != nil {
			continue
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]

			switch v := val.(type) {
			case []byte:
				if utf8.Valid(v) {
					row[col] = string(v)
				} else {
					row[col] = fmt.Sprintf("<binary data: %d bytes>", len(v))
				}
			case time.Time:
				row[col] = v.Format("2006-01-02 15:04:05")
			case nil:
				row[col] = nil
			default:
				row[col] = v
			}
		}
		rows = append(rows, row)
	}

	// Response with metadata
	response := map[string]interface{}{
		"rows":    rows,
		"columns": columns,
		"pagination": map[string]interface{}{
			"page":         page,
			"page_size":    pageSize,
			"total_count":  totalCount,
			"total_pages":  totalPages,
			"has_next":     page < totalPages,
			"has_previous": page > 1,
		},
		"table": map[string]interface{}{
			"schema":          schema,
			"name":            tableName,
			"order_by":        orderBy,
			"order_direction": orderDirection,
		},
		"filters": args["filters"],
	}

	jsonData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error serializing JSON: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

func (s *DatabaseMCP) toolGetTableSchemaFull() (mcp.Tool, server.ToolHandlerFunc) {
	return mcp.Tool{
		Name:        "get_table_schema_full",
		Description: "Returns complete information about a table's structure, including columns, indexes, foreign keys, and constraints",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"table_name": map[string]interface{}{
					"type":        "string",
					"description": "Table name",
				},
				"schema": map[string]interface{}{
					"type":        "string",
					"description": "Schema name (optional, default: dbo)",
				},
			},
			Required: []string{"table_name"},
		},
	}, s.handleGetTableSchemaFull
}

func (s *DatabaseMCP) handleGetTableSchemaFull(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Invalid arguments"), nil
	}

	tableName, ok := args["table_name"].(string)
	if !ok || tableName == "" {
		return mcp.NewToolResultError("Table name is required"), nil
	}

	schema, err := getValidSchema(args, "dbo")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// 1. Search columns
	columnsQuery, columnsQueryArgs := s.queryBuilder.GetTableSchemaFullQuery(schema, tableName)

	rows, err := s.db.QueryContext(ctx, columnsQuery, columnsQueryArgs...)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error retrieving columns: %v", err)), nil
	}

	var columns []map[string]interface{}
	for rows.Next() {
		var columnName, dataType, defaultValue string
		var maxLength, precision, scale int
		var isNullable, isIdentity bool

		if err = rows.Scan(&columnName, &dataType, &maxLength, &precision, &scale, &isNullable, &isIdentity, &defaultValue); err != nil {
			rows.Close()
			return mcp.NewToolResultError(fmt.Sprintf("Error reading column: %v", err)), nil
		}

		column := map[string]interface{}{
			"name":          columnName,
			"type":          dataType,
			"max_length":    maxLength,
			"precision":     precision,
			"scale":         scale,
			"nullable":      isNullable,
			"is_identity":   isIdentity,
			"default_value": defaultValue,
		}
		columns = append(columns, column)
	}
	rows.Close()

	if len(columns) == 0 {
		return mcp.NewToolResultError(fmt.Sprintf("Table '%s.%s' not found", schema, tableName)), nil
	}

	// 2. Search for Primary Key
	pkQuery, pkQueryArgs := s.queryBuilder.GetPrimaryKeyQuery(schema, tableName)

	var pkName, pkColumns sql.NullString
	var primaryKey map[string]interface{}
	err = s.db.QueryRowContext(ctx, pkQuery, pkQueryArgs...).Scan(&pkName, &pkColumns)
	if err == nil && pkName.Valid {
		primaryKey = map[string]interface{}{
			"name":    pkName.String,
			"columns": pkColumns.String,
		}
	}

	// 3. Search Indexes
	indexesQuery, indexesQueryArgs := s.queryBuilder.GetIndexesQuery(schema, tableName)

	rows, err = s.db.QueryContext(ctx, indexesQuery, indexesQueryArgs...)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error while retrieving indexes: %v", err)), nil
	}

	var indexes []map[string]interface{}
	for rows.Next() {
		var indexName, typeDesc, indexColumns string
		var isUnique bool

		if err = rows.Scan(&indexName, &isUnique, &typeDesc, &indexColumns); err != nil {
			rows.Close()
			return mcp.NewToolResultError(fmt.Sprintf("Error reading index: %v", err)), nil
		}

		index := map[string]interface{}{
			"name":      indexName,
			"is_unique": isUnique,
			"type":      typeDesc,
			"columns":   indexColumns,
		}
		indexes = append(indexes, index)
	}
	rows.Close()

	// 4. Search for Foreign Keys
	fkQuery, fkQueryArgs := s.queryBuilder.GetForeignKeysQuery(schema, tableName)

	rows, err = s.db.QueryContext(ctx, fkQuery, fkQueryArgs...)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error retrieving foreign keys: %v", err)), nil
	}

	var foreignKeys []map[string]interface{}
	for rows.Next() {
		var fkName, tableSchema, table, fkColumns, refSchema, refTable, refColumns string

		if err = rows.Scan(&fkName, &tableSchema, &table, &fkColumns, &refSchema, &refTable, &refColumns); err != nil {
			rows.Close()
			return mcp.NewToolResultError(fmt.Sprintf("Error reading foreign key.: %v", err)), nil
		}

		fk := map[string]interface{}{
			"name":               fkName,
			"columns":            fkColumns,
			"referenced_schema":  refSchema,
			"referenced_table":   refTable,
			"referenced_columns": refColumns,
		}
		foreignKeys = append(foreignKeys, fk)
	}
	rows.Close()

	// Assemble a complete response
	response := map[string]interface{}{
		"schema":       schema,
		"table":        tableName,
		"columns":      columns,
		"primary_key":  primaryKey,
		"indexes":      indexes,
		"foreign_keys": foreignKeys,
	}

	jsonData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error serializing JSON: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}
