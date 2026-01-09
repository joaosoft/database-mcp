package mcp

import (
	"fmt"
	"strings"
)

// QueryBuilder provides database-agnostic query building using dialects
type QueryBuilder struct {
	driver  DriverType
	dialect Dialect
}

// NewQueryBuilder creates a new QueryBuilder for the given driver
func NewQueryBuilder(driver string) *QueryBuilder {
	dialect := NewDialect(driver)
	return &QueryBuilder{
		driver:  DriverType(driver),
		dialect: dialect,
	}
}

// -----------------------------------------------------------------------------
// Basic Operations
// -----------------------------------------------------------------------------

// Placeholder returns the correct parameter placeholder for the driver
func (qb *QueryBuilder) Placeholder(index int) string {
	return qb.dialect.Placeholder(index)
}

// LikeOperator returns LIKE or ILIKE depending on driver
func (qb *QueryBuilder) LikeOperator(caseSensitive bool) string {
	return qb.dialect.LikeOperator(caseSensitive)
}

// Concat returns the concat operator for the driver
func (qb *QueryBuilder) Concat(parts ...string) string {
	return qb.dialect.ConcatOperator(parts...)
}

// Limit returns the pagination clause for the driver
func (qb *QueryBuilder) Limit(limit, offset int) string {
	return qb.dialect.PaginationClause(limit, offset, "")
}

// CurrentDatabase returns the function to get current database name
func (qb *QueryBuilder) CurrentDatabase() string {
	return qb.dialect.CurrentDatabase()
}

// QuoteIdentifier returns the properly quoted identifier for the driver
func (qb *QueryBuilder) QuoteIdentifier(name string) string {
	return qb.dialect.QuoteIdentifier(name)
}

// QualifyTable returns the fully qualified table name for the driver
func (qb *QueryBuilder) QualifyTable(schema, tableName string) string {
	if schema == "" || qb.driver == DriverSQLite {
		return qb.QuoteIdentifier(tableName)
	}
	return fmt.Sprintf("%s.%s", qb.QuoteIdentifier(schema), qb.QuoteIdentifier(tableName))
}

// -----------------------------------------------------------------------------
// Pagination Helper
// -----------------------------------------------------------------------------

// appendPaginationClause appends ORDER BY and pagination to a query
// orderByClause should contain the full " ORDER BY col1, col2" or just columns "col1, col2"
func (qb *QueryBuilder) appendPaginationClause(query, orderByClause string, limit, offset int) string {
	// Extract just the columns from orderByClause if it starts with ORDER BY
	orderByColumns := strings.TrimSpace(orderByClause)
	orderByColumns = strings.TrimPrefix(orderByColumns, " ")
	orderByColumns = strings.TrimPrefix(orderByColumns, "ORDER BY ")
	orderByColumns = strings.TrimPrefix(orderByColumns, "order by ")
	orderByColumns = strings.TrimSpace(orderByColumns)

	// For SQL Server and Oracle, ORDER BY must be part of pagination
	switch qb.driver {
	case DriverSQLServer, DriverOracle:
		if orderByColumns == "" {
			orderByColumns = "(SELECT NULL)"
		}
		return query + fmt.Sprintf(" ORDER BY %s OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", orderByColumns, offset, limit)
	default:
		// PostgreSQL, MySQL, SQLite use LIMIT/OFFSET without requiring ORDER BY in pagination
		if orderByColumns != "" {
			query += " ORDER BY " + orderByColumns
		}
		return query + fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}
}

// -----------------------------------------------------------------------------
// Feature Support
// -----------------------------------------------------------------------------

// SupportsStoredProcedures returns true if driver supports stored procedures
func (qb *QueryBuilder) SupportsStoredProcedures() bool {
	return qb.dialect.SupportsFeature(FeatureStoredProcedures)
}

// SupportsFunctions returns true if driver supports functions
func (qb *QueryBuilder) SupportsFunctions() bool {
	return qb.dialect.SupportsFeature(FeatureFunctions)
}

// SupportsTriggers returns true if driver supports triggers
func (qb *QueryBuilder) SupportsTriggers() bool {
	return qb.dialect.SupportsFeature(FeatureTriggers)
}

// SupportsViews returns true if driver supports views
func (qb *QueryBuilder) SupportsViews() bool {
	return qb.dialect.SupportsFeature(FeatureViews)
}

// -----------------------------------------------------------------------------
// Driver Detection
// -----------------------------------------------------------------------------

// GetDriver returns the current driver type
func (qb *QueryBuilder) GetDriver() DriverType {
	return qb.driver
}

// IsPostgres returns true if the driver is PostgreSQL
func (qb *QueryBuilder) IsPostgres() bool {
	return qb.driver == DriverPostgresSQL
}

// IsSQLServer returns true if the driver is SQL Server
func (qb *QueryBuilder) IsSQLServer() bool {
	return qb.driver == DriverSQLServer
}

// IsMySQL returns true if the driver is MySQL
func (qb *QueryBuilder) IsMySQL() bool {
	return qb.driver == DriverMySQL
}

// IsOracle returns true if the driver is Oracle
func (qb *QueryBuilder) IsOracle() bool {
	return qb.driver == DriverOracle
}

// IsSQLite returns true if the driver is SQLite
func (qb *QueryBuilder) IsSQLite() bool {
	return qb.driver == DriverSQLite
}

// -----------------------------------------------------------------------------
// Table Queries
// -----------------------------------------------------------------------------

// ListTablesQuery returns the query to list tables
func (qb *QueryBuilder) ListTablesQuery(schemaFilter, nameFilter string, limit, offset int) (string, []interface{}) {
	meta := qb.dialect.TableMetadata()
	query := meta.ListTables
	var args []interface{}
	argIndex := 1

	if schemaFilter != "" && meta.SchemaFilter != "" {
		query += fmt.Sprintf(meta.SchemaFilter, qb.Placeholder(argIndex))
		args = append(args, qb.dialect.NormalizeIdentifier(schemaFilter))
		argIndex++
	}

	if nameFilter != "" && meta.NameFilter != "" {
		query += fmt.Sprintf(meta.NameFilter, qb.Placeholder(argIndex))
		args = append(args, "%"+qb.dialect.NormalizeIdentifier(nameFilter)+"%")
	}

	query = qb.appendPaginationClause(query, meta.OrderBy, limit, offset)

	return query, args
}

// DescribeTableQuery returns the query to describe table columns
func (qb *QueryBuilder) DescribeTableQuery(schema, tableName string) (string, []interface{}) {
	meta := qb.dialect.TableMetadata()

	if qb.driver == DriverSQLite {
		return fmt.Sprintf(meta.DescribeTable, tableName), []interface{}{}
	}

	return meta.DescribeTable, []interface{}{
		qb.dialect.NormalizeIdentifier(schema),
		qb.dialect.NormalizeIdentifier(tableName),
	}
}

// TableExistsQuery returns query to check if a table exists
func (qb *QueryBuilder) TableExistsQuery(schema, tableName string) (string, []interface{}) {
	meta := qb.dialect.TableMetadata()

	if qb.driver == DriverSQLite {
		return meta.TableExists, []interface{}{tableName}
	}

	return meta.TableExists, []interface{}{
		qb.dialect.NormalizeIdentifier(schema),
		qb.dialect.NormalizeIdentifier(tableName),
	}
}

// GetTableColumnsQuery returns query to get table columns
func (qb *QueryBuilder) GetTableColumnsQuery(schema, tableName string) (string, []interface{}) {
	meta := qb.dialect.TableMetadata()

	if qb.driver == DriverSQLite {
		return fmt.Sprintf(meta.GetColumns, tableName), []interface{}{}
	}

	return meta.GetColumns, []interface{}{
		qb.dialect.NormalizeIdentifier(schema),
		qb.dialect.NormalizeIdentifier(tableName),
	}
}

// GetTableSchemaFullQuery returns query for full table schema
func (qb *QueryBuilder) GetTableSchemaFullQuery(schema, tableName string) (string, []interface{}) {
	meta := qb.dialect.TableMetadata()

	if qb.driver == DriverSQLite {
		return fmt.Sprintf(meta.GetFullSchema, tableName), []interface{}{}
	}

	return meta.GetFullSchema, []interface{}{
		qb.dialect.NormalizeIdentifier(schema),
		qb.dialect.NormalizeIdentifier(tableName),
	}
}

// GetPrimaryKeyQuery returns query to get primary key information
func (qb *QueryBuilder) GetPrimaryKeyQuery(schema, tableName string) (string, []interface{}) {
	meta := qb.dialect.TableMetadata()

	if qb.driver == DriverSQLite {
		return fmt.Sprintf(meta.GetPrimaryKey, tableName), []interface{}{}
	}

	return meta.GetPrimaryKey, []interface{}{
		qb.dialect.NormalizeIdentifier(schema),
		qb.dialect.NormalizeIdentifier(tableName),
	}
}

// GetIndexesQuery returns query to get table indexes
func (qb *QueryBuilder) GetIndexesQuery(schema, tableName string) (string, []interface{}) {
	meta := qb.dialect.TableMetadata()

	if qb.driver == DriverSQLite {
		return fmt.Sprintf(meta.GetIndexes, tableName), []interface{}{}
	}

	return meta.GetIndexes, []interface{}{
		qb.dialect.NormalizeIdentifier(schema),
		qb.dialect.NormalizeIdentifier(tableName),
	}
}

// GetForeignKeysQuery returns query to get foreign key information
func (qb *QueryBuilder) GetForeignKeysQuery(schema, tableName string) (string, []interface{}) {
	meta := qb.dialect.TableMetadata()

	if qb.driver == DriverSQLite {
		return fmt.Sprintf(meta.GetForeignKeys, tableName), []interface{}{}
	}

	return meta.GetForeignKeys, []interface{}{
		qb.dialect.NormalizeIdentifier(schema),
		qb.dialect.NormalizeIdentifier(tableName),
	}
}

// -----------------------------------------------------------------------------
// Procedure Queries
// -----------------------------------------------------------------------------

// ListProceduresQuery returns the query to list stored procedures
func (qb *QueryBuilder) ListProceduresQuery(schemaFilter, nameFilter string, limit, offset int) (string, []interface{}) {
	if !qb.SupportsStoredProcedures() {
		return "", nil
	}

	meta := qb.dialect.ProcedureMetadata()
	query := meta.ListProcedures
	var args []interface{}
	argIndex := 1

	if schemaFilter != "" && meta.SchemaFilter != "" {
		query += fmt.Sprintf(meta.SchemaFilter, qb.Placeholder(argIndex))
		args = append(args, qb.dialect.NormalizeIdentifier(schemaFilter))
		argIndex++
	}

	if nameFilter != "" && meta.NameFilter != "" {
		query += fmt.Sprintf(meta.NameFilter, qb.Placeholder(argIndex))
		args = append(args, "%"+qb.dialect.NormalizeIdentifier(nameFilter)+"%")
	}

	query = qb.appendPaginationClause(query, meta.OrderBy, limit, offset)

	return query, args
}

// GetProcedureCodeQuery returns the query to get procedure source code
func (qb *QueryBuilder) GetProcedureCodeQuery(schema, procedureName string) (string, []interface{}) {
	if !qb.SupportsStoredProcedures() {
		return "", nil
	}

	meta := qb.dialect.ProcedureMetadata()
	return meta.GetCode, []interface{}{
		qb.dialect.NormalizeIdentifier(schema),
		qb.dialect.NormalizeIdentifier(procedureName),
	}
}

// -----------------------------------------------------------------------------
// Function Queries
// -----------------------------------------------------------------------------

// ListFunctionsQuery returns the query to list functions
func (qb *QueryBuilder) ListFunctionsQuery(schemaFilter, nameFilter, funcType string, limit, offset int) (string, []interface{}) {
	if !qb.SupportsFunctions() {
		return "", nil
	}

	meta := qb.dialect.FunctionMetadata()
	query := meta.ListFunctions

	// Add type filter
	switch funcType {
	case "scalar":
		query += meta.TypeFilterScalar
	case "table":
		query += meta.TypeFilterTable
	default:
		query += meta.TypeFilterAll
	}

	var args []interface{}
	argIndex := 1

	if schemaFilter != "" && meta.SchemaFilter != "" {
		query += fmt.Sprintf(meta.SchemaFilter, qb.Placeholder(argIndex))
		args = append(args, qb.dialect.NormalizeIdentifier(schemaFilter))
		argIndex++
	}

	if nameFilter != "" && meta.NameFilter != "" {
		query += fmt.Sprintf(meta.NameFilter, qb.Placeholder(argIndex))
		args = append(args, "%"+qb.dialect.NormalizeIdentifier(nameFilter)+"%")
	}

	query = qb.appendPaginationClause(query, meta.OrderBy, limit, offset)

	return query, args
}

// GetFunctionCodeQuery returns the query to get function source code
func (qb *QueryBuilder) GetFunctionCodeQuery(schema, functionName string) (string, []interface{}) {
	if !qb.SupportsFunctions() {
		return "", nil
	}

	meta := qb.dialect.FunctionMetadata()
	return meta.GetCode, []interface{}{
		qb.dialect.NormalizeIdentifier(schema),
		qb.dialect.NormalizeIdentifier(functionName),
	}
}

// -----------------------------------------------------------------------------
// View Queries
// -----------------------------------------------------------------------------

// ListViewsQuery returns the query to list views
func (qb *QueryBuilder) ListViewsQuery(schemaFilter, nameFilter string, limit, offset int) (string, []interface{}) {
	meta := qb.dialect.ViewMetadata()
	query := meta.ListViews
	var args []interface{}
	argIndex := 1

	if schemaFilter != "" && meta.SchemaFilter != "" {
		query += fmt.Sprintf(meta.SchemaFilter, qb.Placeholder(argIndex))
		args = append(args, qb.dialect.NormalizeIdentifier(schemaFilter))
		argIndex++
	}

	if nameFilter != "" && meta.NameFilter != "" {
		query += fmt.Sprintf(meta.NameFilter, qb.Placeholder(argIndex))
		args = append(args, "%"+qb.dialect.NormalizeIdentifier(nameFilter)+"%")
	}

	query = qb.appendPaginationClause(query, meta.OrderBy, limit, offset)

	return query, args
}

// GetViewDefinitionQuery returns the query to get view definition
func (qb *QueryBuilder) GetViewDefinitionQuery(schema, viewName string) (string, []interface{}) {
	meta := qb.dialect.ViewMetadata()

	if qb.driver == DriverSQLite {
		return meta.GetDefinition, []interface{}{viewName}
	}

	return meta.GetDefinition, []interface{}{
		qb.dialect.NormalizeIdentifier(schema),
		qb.dialect.NormalizeIdentifier(viewName),
	}
}

// -----------------------------------------------------------------------------
// Trigger Queries
// -----------------------------------------------------------------------------

// ListTriggersQuery returns the query to list triggers
func (qb *QueryBuilder) ListTriggersQuery(schemaFilter, tableName, nameFilter string, includeDisabled bool, limit, offset int) (string, []interface{}) {
	meta := qb.dialect.TriggerMetadata()
	query := meta.ListTriggers
	var args []interface{}
	argIndex := 1

	if schemaFilter != "" && meta.SchemaFilter != "" {
		query += fmt.Sprintf(meta.SchemaFilter, qb.Placeholder(argIndex))
		args = append(args, qb.dialect.NormalizeIdentifier(schemaFilter))
		argIndex++
	}

	if tableName != "" && meta.TableFilter != "" {
		query += fmt.Sprintf(meta.TableFilter, qb.Placeholder(argIndex))
		args = append(args, qb.dialect.NormalizeIdentifier(tableName))
		argIndex++
	}

	if nameFilter != "" && meta.NameFilter != "" {
		query += fmt.Sprintf(meta.NameFilter, qb.Placeholder(argIndex))
		args = append(args, "%"+qb.dialect.NormalizeIdentifier(nameFilter)+"%")
	}

	if !includeDisabled && meta.DisabledFilter != "" {
		query += meta.DisabledFilter
	}

	query = qb.appendPaginationClause(query, meta.OrderBy, limit, offset)

	return query, args
}

// GetTriggerCodeQuery returns the query to get trigger source code
func (qb *QueryBuilder) GetTriggerCodeQuery(schema, triggerName string) (string, []interface{}) {
	meta := qb.dialect.TriggerMetadata()

	if qb.driver == DriverSQLite {
		return meta.GetCode, []interface{}{triggerName}
	}

	return meta.GetCode, []interface{}{
		qb.dialect.NormalizeIdentifier(schema),
		qb.dialect.NormalizeIdentifier(triggerName),
	}
}

// -----------------------------------------------------------------------------
// Database Info Queries
// -----------------------------------------------------------------------------

// GetDatabaseInfoQuery returns query for database info
func (qb *QueryBuilder) GetDatabaseInfoQuery() string {
	return qb.dialect.DatabaseInfo().Version
}

// GetDatabaseDetailsQuery returns query for detailed database information
func (qb *QueryBuilder) GetDatabaseDetailsQuery() (string, bool) {
	details := qb.dialect.DatabaseInfo().Details
	return details, details != ""
}

// GetObjectCountsQuery returns query to count database objects
func (qb *QueryBuilder) GetObjectCountsQuery() (string, bool) {
	counts := qb.dialect.DatabaseInfo().ObjectCounts
	return counts, counts != ""
}

// GetSchemasListQuery returns query to list database schemas
func (qb *QueryBuilder) GetSchemasListQuery() (string, bool) {
	schemas := qb.dialect.DatabaseInfo().ListSchemas
	return schemas, schemas != ""
}

// SearchObjectsQuery returns the query to search database objects
func (qb *QueryBuilder) SearchObjectsQuery(searchTerm string, searchInCode bool, objectTypes []string) (string, []interface{}) {
	switch qb.driver {
	case DriverSQLServer:
		return qb.buildSQLServerSearchQuery(searchTerm, searchInCode, objectTypes)
	case DriverPostgresSQL:
		return qb.buildPostgresSearchQuery(searchTerm, searchInCode, objectTypes)
	case DriverMySQL:
		return qb.buildMySQLSearchQuery(searchTerm, objectTypes)
	case DriverOracle:
		return qb.buildOracleSearchQuery(searchTerm, objectTypes)
	case DriverSQLite:
		return qb.buildSQLiteSearchQuery(searchTerm, searchInCode, objectTypes)
	}
	return "", nil
}

// -----------------------------------------------------------------------------
// Search Query Builders (driver-specific due to complexity)
// -----------------------------------------------------------------------------

func (qb *QueryBuilder) buildSQLServerSearchQuery(searchTerm string, searchInCode bool, objectTypes []string) (string, []interface{}) {
	typeMap := map[string]string{
		"table":     "U",
		"view":      "V",
		"procedure": "P",
		"function":  "FN",
	}

	var sqlTypes []string
	if len(objectTypes) > 0 {
		for _, ot := range objectTypes {
			if sqlType, exists := typeMap[ot]; exists {
				sqlTypes = append(sqlTypes, sqlType)
			}
		}
	}
	if len(sqlTypes) == 0 {
		for _, sqlType := range typeMap {
			sqlTypes = append(sqlTypes, sqlType)
		}
	}

	typeInClause := "'" + strings.Join(sqlTypes, "', '") + "'"

	searchInCodeClause := ""
	if searchInCode {
		searchInCodeClause = "OR (m.definition IS NOT NULL AND m.definition LIKE '%' + @p1 + '%')"
	}

	query := fmt.Sprintf(`
		SELECT DISTINCT
			s.name AS schema_name,
			o.name AS object_name,
			o.type_desc AS object_type,
			o.create_date,
			o.modify_date,
			CASE WHEN m.definition IS NOT NULL THEN 1 ELSE 0 END AS has_code
		FROM sys.objects o
		INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
		LEFT JOIN sys.sql_modules m ON o.object_id = m.object_id
		WHERE o.type IN (%s)
		  AND (o.name LIKE '%%' + @p1 + '%%' %s)
		ORDER BY s.name, o.name`, typeInClause, searchInCodeClause)

	return query, []interface{}{searchTerm}
}

func (qb *QueryBuilder) buildPostgresSearchQuery(searchTerm string, searchInCode bool, objectTypes []string) (string, []interface{}) {
	objectTypeFilter := ""
	if len(objectTypes) > 0 {
		var types []string
		for _, ot := range objectTypes {
			switch ot {
			case "table":
				types = append(types, "'BASE TABLE'")
			case "view":
				types = append(types, "'VIEW'")
			}
		}
		if len(types) > 0 {
			objectTypeFilter = " AND table_type IN (" + strings.Join(types, ",") + ")"
		}
	}

	searchInCodeClause := ""
	if searchInCode {
		searchInCodeClause = " OR view_definition LIKE '%' || $1 || '%'"
	}

	query := fmt.Sprintf(`
		SELECT
			table_schema AS schema_name,
			table_name AS object_name,
			table_type AS object_type,
			NULL AS create_date,
			NULL AS modify_date,
			CASE WHEN view_definition IS NOT NULL THEN 1 ELSE 0 END AS has_code
		FROM information_schema.tables
		LEFT JOIN information_schema.views USING (table_schema, table_name)
		WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
		  AND (table_name LIKE '%%' || $1 || '%%' %s)
		  %s
		ORDER BY table_schema, table_name`, searchInCodeClause, objectTypeFilter)

	return query, []interface{}{searchTerm}
}

func (qb *QueryBuilder) buildMySQLSearchQuery(searchTerm string, objectTypes []string) (string, []interface{}) {
	objectTypeFilter := ""
	if len(objectTypes) > 0 {
		var types []string
		for _, ot := range objectTypes {
			switch ot {
			case "table":
				types = append(types, "'BASE TABLE'")
			case "view":
				types = append(types, "'VIEW'")
			}
		}
		if len(types) > 0 {
			objectTypeFilter = " AND TABLE_TYPE IN (" + strings.Join(types, ",") + ")"
		}
	}

	query := fmt.Sprintf(`
		SELECT
			TABLE_SCHEMA AS schema_name,
			TABLE_NAME AS object_name,
			TABLE_TYPE AS object_type,
			CREATE_TIME AS create_date,
			UPDATE_TIME AS modify_date,
			0 AS has_code
		FROM INFORMATION_SCHEMA.TABLES
		WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
		  AND TABLE_NAME LIKE CONCAT('%%', ?, '%%')
		  %s
		ORDER BY TABLE_SCHEMA, TABLE_NAME`, objectTypeFilter)

	return query, []interface{}{searchTerm}
}

func (qb *QueryBuilder) buildOracleSearchQuery(searchTerm string, objectTypes []string) (string, []interface{}) {
	objectTypeFilter := ""
	if len(objectTypes) > 0 {
		var types []string
		for _, ot := range objectTypes {
			switch ot {
			case "table":
				types = append(types, "'TABLE'")
			case "view":
				types = append(types, "'VIEW'")
			case "procedure":
				types = append(types, "'PROCEDURE'")
			case "function":
				types = append(types, "'FUNCTION'")
			}
		}
		if len(types) > 0 {
			objectTypeFilter = " AND object_type IN (" + strings.Join(types, ",") + ")"
		}
	}

	query := fmt.Sprintf(`
		SELECT
			owner AS schema_name,
			object_name,
			object_type,
			created AS create_date,
			last_ddl_time AS modify_date,
			0 AS has_code
		FROM all_objects
		WHERE owner NOT IN ('SYS', 'SYSTEM')
		  AND object_name LIKE '%%' || :1 || '%%'
		  %s
		ORDER BY owner, object_name`, objectTypeFilter)

	return query, []interface{}{strings.ToUpper(searchTerm)}
}

func (qb *QueryBuilder) buildSQLiteSearchQuery(searchTerm string, searchInCode bool, objectTypes []string) (string, []interface{}) {
	objectTypeFilter := ""
	if len(objectTypes) > 0 {
		var types []string
		for _, ot := range objectTypes {
			switch ot {
			case "table":
				types = append(types, "'table'")
			case "view":
				types = append(types, "'view'")
			case "trigger":
				types = append(types, "'trigger'")
			}
		}
		if len(types) > 0 {
			objectTypeFilter = " AND type IN (" + strings.Join(types, ",") + ")"
		}
	}

	searchInCodeClause := ""
	if searchInCode {
		searchInCodeClause = " OR sql LIKE '%' || ? || '%'"
	}

	query := fmt.Sprintf(`
		SELECT
			'' AS schema_name,
			name AS object_name,
			type AS object_type,
			NULL AS create_date,
			NULL AS modify_date,
			CASE WHEN sql IS NOT NULL THEN 1 ELSE 0 END AS has_code
		FROM sqlite_master
		WHERE name NOT LIKE 'sqlite_%%'
		  AND (name LIKE '%%' || ? || '%%' %s)
		  %s
		ORDER BY name`, searchInCodeClause, objectTypeFilter)

	if searchInCode {
		return query, []interface{}{searchTerm, searchTerm}
	}
	return query, []interface{}{searchTerm}
}

// -----------------------------------------------------------------------------
// Select/Count Query Building
// -----------------------------------------------------------------------------

// BuildSelectQuery builds a SELECT query with pagination based on the driver
func (qb *QueryBuilder) BuildSelectQuery(params SelectQueryParams) string {
	qualifiedTable := qb.QualifyTable(params.Schema, params.Table)

	var quotedColumns []string
	for _, col := range params.Columns {
		quotedColumns = append(quotedColumns, qb.QuoteIdentifier(col))
	}
	columnsStr := strings.Join(quotedColumns, ", ")

	quotedOrderBy := qb.QuoteIdentifier(params.OrderBy)
	orderClause := fmt.Sprintf("%s %s", quotedOrderBy, params.OrderDirection)

	baseQuery := fmt.Sprintf(`SELECT %s FROM %s %s`, columnsStr, qualifiedTable, params.WhereClause)
	return qb.appendPaginationClause(baseQuery, orderClause, params.Limit, params.Offset)
}

// BuildCountQuery builds a COUNT query
func (qb *QueryBuilder) BuildCountQuery(schema, table, whereClause string) string {
	qualifiedTable := qb.QualifyTable(schema, table)
	return fmt.Sprintf("SELECT COUNT(*) FROM %s %s", qualifiedTable, whereClause)
}
