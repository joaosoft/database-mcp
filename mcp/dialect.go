package mcp

import "fmt"

// Dialect defines the interface for database-specific SQL generation
type Dialect interface {
	// Driver returns the driver type
	Driver() DriverType

	// Placeholder returns the parameter placeholder for the given index (1-based)
	Placeholder(index int) string

	// QuoteIdentifier quotes an identifier (table, column name)
	QuoteIdentifier(name string) string

	// PaginationClause returns the pagination SQL clause
	// orderBy is optional - some databases require ORDER BY for pagination
	PaginationClause(limit, offset int, orderBy string) string

	// LikeOperator returns LIKE or ILIKE depending on case sensitivity
	LikeOperator(caseSensitive bool) string

	// ConcatOperator returns the concatenation expression for the given parts
	ConcatOperator(parts ...string) string

	// CurrentDatabase returns the SQL expression for current database name
	CurrentDatabase() string

	// SystemSchemas returns the list of system schemas to exclude
	SystemSchemas() []string

	// NormalizeIdentifier normalizes an identifier (e.g., Oracle uses UPPER)
	NormalizeIdentifier(name string) string

	// SupportsFeature checks if the dialect supports a specific feature
	SupportsFeature(feature DialectFeature) bool

	// TableMetadata returns SQL components for table metadata queries
	TableMetadata() TableMetadataSQL

	// ProcedureMetadata returns SQL components for procedure metadata queries
	ProcedureMetadata() ProcedureMetadataSQL

	// FunctionMetadata returns SQL components for function metadata queries
	FunctionMetadata() FunctionMetadataSQL

	// ViewMetadata returns SQL components for view metadata queries
	ViewMetadata() ViewMetadataSQL

	// TriggerMetadata returns SQL components for trigger metadata queries
	TriggerMetadata() TriggerMetadataSQL

	// DatabaseInfo returns SQL for database information queries
	DatabaseInfo() DatabaseInfoSQL
}

// DialectFeature represents a database feature
type DialectFeature int

const (
	FeatureStoredProcedures DialectFeature = iota
	FeatureFunctions
	FeatureTriggers
	FeatureViews
	FeatureSchemas
	FeatureILike
)

// TableMetadataSQL contains SQL templates for table operations
type TableMetadataSQL struct {
	// ListTables base query (without filters)
	ListTables string
	// Columns to select: schema, name, type
	ListTablesColumns string
	// Filter for schema
	SchemaFilter string
	// Filter for name (LIKE)
	NameFilter string
	// Order by clause
	OrderBy string

	// DescribeTable query
	DescribeTable string

	// TableExists query
	TableExists string

	// GetColumns query
	GetColumns string

	// GetFullSchema query (with primary key info)
	GetFullSchema string

	// GetPrimaryKey query
	GetPrimaryKey string

	// GetIndexes query
	GetIndexes string

	// GetForeignKeys query
	GetForeignKeys string
}

// ProcedureMetadataSQL contains SQL templates for procedure operations
type ProcedureMetadataSQL struct {
	// ListProcedures base query
	ListProcedures string
	// SchemaFilter
	SchemaFilter string
	// NameFilter
	NameFilter string
	// OrderBy
	OrderBy string
	// GetCode query
	GetCode string
}

// FunctionMetadataSQL contains SQL templates for function operations
type FunctionMetadataSQL struct {
	// ListFunctions base query
	ListFunctions string
	// TypeFilter for scalar/table functions
	TypeFilterScalar string
	TypeFilterTable  string
	TypeFilterAll    string
	// SchemaFilter
	SchemaFilter string
	// NameFilter
	NameFilter string
	// OrderBy
	OrderBy string
	// GetCode query
	GetCode string
}

// ViewMetadataSQL contains SQL templates for view operations
type ViewMetadataSQL struct {
	// ListViews base query
	ListViews string
	// SchemaFilter
	SchemaFilter string
	// NameFilter
	NameFilter string
	// OrderBy
	OrderBy string
	// GetDefinition query
	GetDefinition string
}

// TriggerMetadataSQL contains SQL templates for trigger operations
type TriggerMetadataSQL struct {
	// ListTriggers base query
	ListTriggers string
	// SchemaFilter
	SchemaFilter string
	// TableFilter
	TableFilter string
	// NameFilter
	NameFilter string
	// DisabledFilter (to exclude disabled)
	DisabledFilter string
	// OrderBy
	OrderBy string
	// GetCode query
	GetCode string
}

// DatabaseInfoSQL contains SQL for database info queries
type DatabaseInfoSQL struct {
	// Version query
	Version string
	// Details query (database name, collation, etc.)
	Details string
	// ObjectCounts query
	ObjectCounts string
	// ListSchemas query
	ListSchemas string
	// SearchObjects query template
	SearchObjects string
}

// BaseDialect provides common functionality for all dialects
type BaseDialect struct {
	driver DriverType
}

// Driver returns the driver type
func (d *BaseDialect) Driver() DriverType {
	return d.driver
}

// NormalizeIdentifier default implementation - strips brackets if present
func (d *BaseDialect) NormalizeIdentifier(name string) string {
	// Remove SQL Server style brackets [name] if present
	if len(name) >= 2 && name[0] == '[' && name[len(name)-1] == ']' {
		return name[1 : len(name)-1]
	}
	return name
}

// LikeOperator default implementation
func (d *BaseDialect) LikeOperator(caseSensitive bool) string {
	return "LIKE"
}

// SupportsFeature default implementation (all features supported except specifics)
func (d *BaseDialect) SupportsFeature(feature DialectFeature) bool {
	return true
}

// QualifyTable returns the fully qualified table name
func QualifyTable(d Dialect, schema, tableName string) string {
	if schema == "" {
		return d.QuoteIdentifier(tableName)
	}
	return fmt.Sprintf("%s.%s", d.QuoteIdentifier(schema), d.QuoteIdentifier(tableName))
}

// BuildPlaceholderList builds a list of placeholders for the given count starting at startIndex
func BuildPlaceholderList(d Dialect, startIndex, count int) []string {
	placeholders := make([]string, count)
	for i := 0; i < count; i++ {
		placeholders[i] = d.Placeholder(startIndex + i)
	}
	return placeholders
}

// NewDialect creates a new dialect for the given driver
func NewDialect(driver string) Dialect {
	switch DriverType(driver) {
	case DriverSQLServer:
		return NewSQLServerDialect()
	case DriverPostgresSQL:
		return NewPostgresDialect()
	case DriverMySQL:
		return NewMySQLDialect()
	case DriverOracle:
		return NewOracleDialect()
	case DriverSQLite:
		return NewSQLiteDialect()
	default:
		// Default to PostgreSQL-like syntax
		return NewPostgresDialect()
	}
}
