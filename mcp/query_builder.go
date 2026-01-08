package mcp

import (
	"fmt"
	"strings"
)

type DriverType string

const (
	DriverSQLServer   DriverType = "sqlserver"
	DriverPostgreSQL  DriverType = "postgres"
	DriverMySQL       DriverType = "mysql"
	DriverOracle      DriverType = "godror"
	DriverSQLite      DriverType = "sqlite3"
)

type QueryBuilder struct {
	driver DriverType
}

func NewQueryBuilder(driver string) *QueryBuilder {
	return &QueryBuilder{driver: DriverType(driver)}
}

// Placeholder returns the correct parameter placeholder for the driver
func (qb *QueryBuilder) Placeholder(index int) string {
	switch qb.driver {
	case DriverPostgreSQL:
		return fmt.Sprintf("$%d", index)
	case DriverOracle:
		return fmt.Sprintf(":%d", index)
	case DriverMySQL, DriverSQLite:
		return "?"
	case DriverSQLServer:
		return fmt.Sprintf("@p%d", index)
	default:
		return "?"
	}
}

// LikeOperator returns LIKE or ILIKE depending on driver
func (qb *QueryBuilder) LikeOperator(caseSensitive bool) string {
	if !caseSensitive && qb.driver == DriverPostgreSQL {
		return "ILIKE"
	}
	return "LIKE"
}

// Concat returns the concat operator for the driver
func (qb *QueryBuilder) Concat(parts ...string) string {
	switch qb.driver {
	case DriverSQLServer:
		return strings.Join(parts, " + ")
	case DriverPostgreSQL, DriverSQLite:
		return strings.Join(parts, " || ")
	case DriverMySQL:
		return "CONCAT(" + strings.Join(parts, ", ") + ")"
	case DriverOracle:
		return strings.Join(parts, " || ")
	default:
		return strings.Join(parts, " || ")
	}
}

// Limit returns the pagination clause for the driver
func (qb *QueryBuilder) Limit(limit, offset int) string {
	switch qb.driver {
	case DriverSQLServer:
		return fmt.Sprintf("ORDER BY (SELECT NULL) OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, limit)
	case DriverOracle:
		return fmt.Sprintf("OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, limit)
	case DriverPostgreSQL, DriverMySQL, DriverSQLite:
		return fmt.Sprintf("LIMIT %d OFFSET %d", limit, offset)
	default:
		return fmt.Sprintf("LIMIT %d OFFSET %d", limit, offset)
	}
}

// CurrentDatabase returns the function to get current database name
func (qb *QueryBuilder) CurrentDatabase() string {
	switch qb.driver {
	case DriverSQLServer:
		return "DB_NAME()"
	case DriverPostgreSQL:
		return "current_database()"
	case DriverMySQL:
		return "DATABASE()"
	case DriverOracle:
		return "SYS_CONTEXT('USERENV', 'DB_NAME')"
	case DriverSQLite:
		return "'main'"
	default:
		return "DATABASE()"
	}
}

// ListTablesQuery returns the query to list tables
func (qb *QueryBuilder) ListTablesQuery(schemaFilter, nameFilter string, limit, offset int) (string, []interface{}) {
	var query string
	var args []interface{}
	argIndex := 1

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT
				TABLE_SCHEMA,
				TABLE_NAME,
				TABLE_TYPE
			FROM INFORMATION_SCHEMA.TABLES
			WHERE TABLE_TYPE = 'BASE TABLE'`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND TABLE_SCHEMA = %s", qb.Placeholder(argIndex))
			args = append(args, schemaFilter)
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND TABLE_NAME LIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+nameFilter+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY TABLE_SCHEMA, TABLE_NAME OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, limit)

	case DriverPostgreSQL:
		query = `
			SELECT
				table_schema,
				table_name,
				table_type
			FROM information_schema.tables
			WHERE table_type = 'BASE TABLE'
				AND table_schema NOT IN ('pg_catalog', 'information_schema')`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND table_schema = %s", qb.Placeholder(argIndex))
			args = append(args, schemaFilter)
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND table_name ILIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+nameFilter+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY table_schema, table_name LIMIT %d OFFSET %d", limit, offset)

	case DriverMySQL:
		query = `
			SELECT
				TABLE_SCHEMA,
				TABLE_NAME,
				TABLE_TYPE
			FROM INFORMATION_SCHEMA.TABLES
			WHERE TABLE_TYPE = 'BASE TABLE'
				AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')`

		if schemaFilter != "" {
			query += " AND TABLE_SCHEMA = ?"
			args = append(args, schemaFilter)
		}

		if nameFilter != "" {
			query += " AND TABLE_NAME LIKE ?"
			args = append(args, "%"+nameFilter+"%")
		}

		query += fmt.Sprintf(" ORDER BY TABLE_SCHEMA, TABLE_NAME LIMIT %d OFFSET %d", limit, offset)

	case DriverSQLite:
		query = `
			SELECT
				'main' as table_schema,
				name as table_name,
				'BASE TABLE' as table_type
			FROM sqlite_master
			WHERE type = 'table'
				AND name NOT LIKE 'sqlite_%'`

		if nameFilter != "" {
			query += " AND name LIKE ?"
			args = append(args, "%"+nameFilter+"%")
		}

		query += fmt.Sprintf(" ORDER BY name LIMIT %d OFFSET %d", limit, offset)

	case DriverOracle:
		query = `
			SELECT
				owner as table_schema,
				table_name,
				'BASE TABLE' as table_type
			FROM all_tables
			WHERE owner NOT IN ('SYS', 'SYSTEM', 'OUTLN', 'XDB', 'WMSYS', 'CTXSYS', 'MDSYS', 'OLAPSYS')`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND owner = %s", qb.Placeholder(argIndex))
			args = append(args, schemaFilter)
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND table_name LIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+strings.ToUpper(nameFilter)+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY owner, table_name OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, limit)
	}

	return query, args
}

// DescribeTableQuery returns the query to describe table columns
func (qb *QueryBuilder) DescribeTableQuery(schema, tableName string) (string, []interface{}) {
	var query string
	var args []interface{}

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT
				COLUMN_NAME,
				DATA_TYPE,
				IS_NULLABLE,
				COLUMN_DEFAULT,
				CHARACTER_MAXIMUM_LENGTH
			FROM INFORMATION_SCHEMA.COLUMNS
			WHERE TABLE_SCHEMA = @p1 AND TABLE_NAME = @p2
			ORDER BY ORDINAL_POSITION`
		args = []interface{}{schema, tableName}

	case DriverPostgreSQL:
		query = `
			SELECT
				column_name,
				data_type,
				is_nullable,
				column_default,
				character_maximum_length
			FROM information_schema.columns
			WHERE table_schema = $1 AND table_name = $2
			ORDER BY ordinal_position`
		args = []interface{}{schema, tableName}

	case DriverMySQL:
		query = `
			SELECT
				COLUMN_NAME,
				DATA_TYPE,
				IS_NULLABLE,
				COLUMN_DEFAULT,
				CHARACTER_MAXIMUM_LENGTH
			FROM INFORMATION_SCHEMA.COLUMNS
			WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
			ORDER BY ORDINAL_POSITION`
		args = []interface{}{schema, tableName}

	case DriverSQLite:
		query = fmt.Sprintf("PRAGMA table_info(%s)", tableName)
		args = []interface{}{}

	case DriverOracle:
		query = `
			SELECT
				column_name,
				data_type,
				nullable as is_nullable,
				data_default as column_default,
				data_length as character_maximum_length
			FROM all_tab_columns
			WHERE owner = :1 AND table_name = :2
			ORDER BY column_id`
		args = []interface{}{strings.ToUpper(schema), strings.ToUpper(tableName)}
	}

	return query, args
}

// TableExistsQuery returns query to check if a table exists
func (qb *QueryBuilder) TableExistsQuery(schema, tableName string) (string, []interface{}) {
	var query string
	var args []interface{}

	switch qb.driver {
	case DriverSQLServer:
		query = "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = @p1 AND TABLE_NAME = @p2"
		args = []interface{}{schema, tableName}
	case DriverPostgreSQL:
		query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2"
		args = []interface{}{schema, tableName}
	case DriverMySQL:
		query = "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?"
		args = []interface{}{schema, tableName}
	case DriverOracle:
		query = "SELECT COUNT(*) FROM all_tables WHERE owner = :1 AND table_name = :2"
		args = []interface{}{strings.ToUpper(schema), strings.ToUpper(tableName)}
	case DriverSQLite:
		query = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?"
		args = []interface{}{tableName}
	}

	return query, args
}

// GetTableColumnsQuery returns query to get table columns
func (qb *QueryBuilder) GetTableColumnsQuery(schema, tableName string) (string, []interface{}) {
	var query string
	var args []interface{}

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT
				COLUMN_NAME,
				DATA_TYPE,
				CHARACTER_MAXIMUM_LENGTH,
				IS_NULLABLE,
				COLUMN_DEFAULT
			FROM INFORMATION_SCHEMA.COLUMNS
			WHERE TABLE_SCHEMA = @p1 AND TABLE_NAME = @p2
			ORDER BY ORDINAL_POSITION`
		args = []interface{}{schema, tableName}
	case DriverPostgreSQL:
		query = `
			SELECT
				column_name,
				data_type,
				character_maximum_length,
				is_nullable,
				column_default
			FROM information_schema.columns
			WHERE table_schema = $1 AND table_name = $2
			ORDER BY ordinal_position`
		args = []interface{}{schema, tableName}
	case DriverMySQL:
		query = `
			SELECT
				COLUMN_NAME,
				DATA_TYPE,
				CHARACTER_MAXIMUM_LENGTH,
				IS_NULLABLE,
				COLUMN_DEFAULT
			FROM INFORMATION_SCHEMA.COLUMNS
			WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
			ORDER BY ORDINAL_POSITION`
		args = []interface{}{schema, tableName}
	case DriverOracle:
		query = `
			SELECT
				column_name,
				data_type,
				data_length,
				nullable,
				data_default
			FROM all_tab_columns
			WHERE owner = :1 AND table_name = :2
			ORDER BY column_id`
		args = []interface{}{strings.ToUpper(schema), strings.ToUpper(tableName)}
	case DriverSQLite:
		query = fmt.Sprintf("PRAGMA table_info(%s)", tableName)
		args = []interface{}{}
	}

	return query, args
}

// GetTableSchemaFullQuery returns query for full table schema
func (qb *QueryBuilder) GetTableSchemaFullQuery(schema, tableName string) (string, []interface{}) {
	var query string
	var args []interface{}

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT
				c.COLUMN_NAME,
				c.DATA_TYPE,
				c.CHARACTER_MAXIMUM_LENGTH,
				c.NUMERIC_PRECISION,
				c.NUMERIC_SCALE,
				c.IS_NULLABLE,
				c.COLUMN_DEFAULT,
				CASE WHEN pk.COLUMN_NAME IS NOT NULL THEN 'YES' ELSE 'NO' END AS IS_PRIMARY_KEY
			FROM INFORMATION_SCHEMA.COLUMNS c
			LEFT JOIN (
				SELECT ku.TABLE_SCHEMA, ku.TABLE_NAME, ku.COLUMN_NAME
				FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
				JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE ku
					ON tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
					AND tc.CONSTRAINT_NAME = ku.CONSTRAINT_NAME
					AND tc.TABLE_SCHEMA = ku.TABLE_SCHEMA
					AND tc.TABLE_NAME = ku.TABLE_NAME
			) pk ON c.TABLE_SCHEMA = pk.TABLE_SCHEMA
				AND c.TABLE_NAME = pk.TABLE_NAME
				AND c.COLUMN_NAME = pk.COLUMN_NAME
			WHERE c.TABLE_SCHEMA = @p1 AND c.TABLE_NAME = @p2
			ORDER BY c.ORDINAL_POSITION`
		args = []interface{}{schema, tableName}
	case DriverPostgreSQL:
		query = `
			SELECT
				c.column_name,
				c.data_type,
				c.character_maximum_length,
				c.numeric_precision,
				c.numeric_scale,
				c.is_nullable,
				c.column_default,
				CASE WHEN pk.column_name IS NOT NULL THEN 'YES' ELSE 'NO' END AS is_primary_key
			FROM information_schema.columns c
			LEFT JOIN (
				SELECT ku.table_schema, ku.table_name, ku.column_name
				FROM information_schema.table_constraints tc
				JOIN information_schema.key_column_usage ku
					ON tc.constraint_type = 'PRIMARY KEY'
					AND tc.constraint_name = ku.constraint_name
					AND tc.table_schema = ku.table_schema
					AND tc.table_name = ku.table_name
			) pk ON c.table_schema = pk.table_schema
				AND c.table_name = pk.table_name
				AND c.column_name = pk.column_name
			WHERE c.table_schema = $1 AND c.table_name = $2
			ORDER BY c.ordinal_position`
		args = []interface{}{schema, tableName}
	case DriverMySQL:
		query = `
			SELECT
				c.COLUMN_NAME,
				c.DATA_TYPE,
				c.CHARACTER_MAXIMUM_LENGTH,
				c.NUMERIC_PRECISION,
				c.NUMERIC_SCALE,
				c.IS_NULLABLE,
				c.COLUMN_DEFAULT,
				CASE WHEN pk.COLUMN_NAME IS NOT NULL THEN 'YES' ELSE 'NO' END AS IS_PRIMARY_KEY
			FROM INFORMATION_SCHEMA.COLUMNS c
			LEFT JOIN (
				SELECT ku.TABLE_SCHEMA, ku.TABLE_NAME, ku.COLUMN_NAME
				FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
				JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE ku
					ON tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
					AND tc.CONSTRAINT_NAME = ku.CONSTRAINT_NAME
					AND tc.TABLE_SCHEMA = ku.TABLE_SCHEMA
					AND tc.TABLE_NAME = ku.TABLE_NAME
			) pk ON c.TABLE_SCHEMA = pk.TABLE_SCHEMA
				AND c.TABLE_NAME = pk.TABLE_NAME
				AND c.COLUMN_NAME = pk.COLUMN_NAME
			WHERE c.TABLE_SCHEMA = ? AND c.TABLE_NAME = ?
			ORDER BY c.ORDINAL_POSITION`
		args = []interface{}{schema, tableName}
	case DriverOracle:
		query = `
			SELECT
				c.column_name,
				c.data_type,
				c.data_length,
				c.data_precision,
				c.data_scale,
				c.nullable,
				c.data_default,
				CASE WHEN pk.column_name IS NOT NULL THEN 'YES' ELSE 'NO' END AS is_primary_key
			FROM all_tab_columns c
			LEFT JOIN (
				SELECT acc.owner, acc.table_name, acc.column_name
				FROM all_constraints ac
				JOIN all_cons_columns acc
					ON ac.constraint_type = 'P'
					AND ac.constraint_name = acc.constraint_name
					AND ac.owner = acc.owner
			) pk ON c.owner = pk.owner
				AND c.table_name = pk.table_name
				AND c.column_name = pk.column_name
			WHERE c.owner = :1 AND c.table_name = :2
			ORDER BY c.column_id`
		args = []interface{}{strings.ToUpper(schema), strings.ToUpper(tableName)}
	case DriverSQLite:
		query = fmt.Sprintf("PRAGMA table_info(%s)", tableName)
		args = []interface{}{}
	}

	return query, args
}

// GetPrimaryKeyQuery returns query to get primary key information
func (qb *QueryBuilder) GetPrimaryKeyQuery(schema, tableName string) (string, []interface{}) {
	var query string
	var args []interface{}

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT ku.COLUMN_NAME
			FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
			JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE ku
				ON tc.CONSTRAINT_NAME = ku.CONSTRAINT_NAME
				AND tc.TABLE_SCHEMA = ku.TABLE_SCHEMA
				AND tc.TABLE_NAME = ku.TABLE_NAME
			WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
				AND tc.TABLE_SCHEMA = @p1
				AND tc.TABLE_NAME = @p2
			ORDER BY ku.ORDINAL_POSITION`
		args = []interface{}{schema, tableName}
	case DriverPostgreSQL:
		query = `
			SELECT ku.column_name
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage ku
				ON tc.constraint_name = ku.constraint_name
				AND tc.table_schema = ku.table_schema
				AND tc.table_name = ku.table_name
			WHERE tc.constraint_type = 'PRIMARY KEY'
				AND tc.table_schema = $1
				AND tc.table_name = $2
			ORDER BY ku.ordinal_position`
		args = []interface{}{schema, tableName}
	case DriverMySQL:
		query = `
			SELECT ku.COLUMN_NAME
			FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
			JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE ku
				ON tc.CONSTRAINT_NAME = ku.CONSTRAINT_NAME
				AND tc.TABLE_SCHEMA = ku.TABLE_SCHEMA
				AND tc.TABLE_NAME = ku.TABLE_NAME
			WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
				AND tc.TABLE_SCHEMA = ?
				AND tc.TABLE_NAME = ?
			ORDER BY ku.ORDINAL_POSITION`
		args = []interface{}{schema, tableName}
	case DriverOracle:
		query = `
			SELECT acc.column_name
			FROM all_constraints ac
			JOIN all_cons_columns acc
				ON ac.constraint_name = acc.constraint_name
				AND ac.owner = acc.owner
			WHERE ac.constraint_type = 'P'
				AND ac.owner = :1
				AND ac.table_name = :2
			ORDER BY acc.position`
		args = []interface{}{strings.ToUpper(schema), strings.ToUpper(tableName)}
	case DriverSQLite:
		query = fmt.Sprintf("PRAGMA table_info(%s)", tableName)
		args = []interface{}{}
	}

	return query, args
}

// GetIndexesQuery returns query to get table indexes
func (qb *QueryBuilder) GetIndexesQuery(schema, tableName string) (string, []interface{}) {
	var query string
	var args []interface{}

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT
				i.name AS index_name,
				i.type_desc AS index_type,
				i.is_unique,
				COL_NAME(ic.object_id, ic.column_id) AS column_name
			FROM sys.indexes i
			INNER JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
			INNER JOIN sys.tables t ON i.object_id = t.object_id
			INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
			WHERE s.name = @p1 AND t.name = @p2
			ORDER BY i.name, ic.key_ordinal`
		args = []interface{}{schema, tableName}
	case DriverPostgreSQL:
		query = `
			SELECT
				i.indexname AS index_name,
				a.amname AS index_type,
				ix.indisunique AS is_unique,
				a2.attname AS column_name
			FROM pg_indexes i
			JOIN pg_class c ON i.indexname = c.relname
			JOIN pg_index ix ON c.oid = ix.indexrelid
			JOIN pg_class t ON ix.indrelid = t.oid
			JOIN pg_namespace n ON t.relnamespace = n.oid
			JOIN pg_am a ON c.relam = a.oid
			JOIN pg_attribute a2 ON a2.attrelid = t.oid AND a2.attnum = ANY(ix.indkey)
			WHERE n.nspname = $1 AND t.relname = $2
			ORDER BY i.indexname`
		args = []interface{}{schema, tableName}
	case DriverMySQL:
		query = `
			SELECT
				INDEX_NAME AS index_name,
				INDEX_TYPE AS index_type,
				CASE WHEN NON_UNIQUE = 0 THEN 1 ELSE 0 END AS is_unique,
				COLUMN_NAME AS column_name
			FROM INFORMATION_SCHEMA.STATISTICS
			WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
			ORDER BY INDEX_NAME, SEQ_IN_INDEX`
		args = []interface{}{schema, tableName}
	case DriverOracle:
		query = `
			SELECT
				i.index_name,
				i.index_type,
				i.uniqueness,
				ic.column_name
			FROM all_indexes i
			JOIN all_ind_columns ic ON i.index_name = ic.index_name AND i.owner = ic.index_owner
			WHERE i.owner = :1 AND i.table_name = :2
			ORDER BY i.index_name, ic.column_position`
		args = []interface{}{strings.ToUpper(schema), strings.ToUpper(tableName)}
	case DriverSQLite:
		query = fmt.Sprintf("PRAGMA index_list(%s)", tableName)
		args = []interface{}{}
	}

	return query, args
}

// GetForeignKeysQuery returns query to get foreign key information
func (qb *QueryBuilder) GetForeignKeysQuery(schema, tableName string) (string, []interface{}) {
	var query string
	var args []interface{}

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT
				fk.name AS constraint_name,
				COL_NAME(fkc.parent_object_id, fkc.parent_column_id) AS column_name,
				SCHEMA_NAME(ref_t.schema_id) AS referenced_schema,
				ref_t.name AS referenced_table,
				COL_NAME(fkc.referenced_object_id, fkc.referenced_column_id) AS referenced_column
			FROM sys.foreign_keys fk
			INNER JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
			INNER JOIN sys.tables t ON fk.parent_object_id = t.object_id
			INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
			INNER JOIN sys.tables ref_t ON fkc.referenced_object_id = ref_t.object_id
			WHERE s.name = @p1 AND t.name = @p2
			ORDER BY fk.name`
		args = []interface{}{schema, tableName}
	case DriverPostgreSQL:
		query = `
			SELECT
				tc.constraint_name,
				kcu.column_name,
				ccu.table_schema AS referenced_schema,
				ccu.table_name AS referenced_table,
				ccu.column_name AS referenced_column
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage kcu
				ON tc.constraint_name = kcu.constraint_name
				AND tc.table_schema = kcu.table_schema
			JOIN information_schema.constraint_column_usage ccu
				ON ccu.constraint_name = tc.constraint_name
				AND ccu.table_schema = tc.table_schema
			WHERE tc.constraint_type = 'FOREIGN KEY'
				AND tc.table_schema = $1
				AND tc.table_name = $2
			ORDER BY tc.constraint_name`
		args = []interface{}{schema, tableName}
	case DriverMySQL:
		query = `
			SELECT
				kcu.CONSTRAINT_NAME AS constraint_name,
				kcu.COLUMN_NAME AS column_name,
				kcu.REFERENCED_TABLE_SCHEMA AS referenced_schema,
				kcu.REFERENCED_TABLE_NAME AS referenced_table,
				kcu.REFERENCED_COLUMN_NAME AS referenced_column
			FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu
			WHERE kcu.TABLE_SCHEMA = ?
				AND kcu.TABLE_NAME = ?
				AND kcu.REFERENCED_TABLE_NAME IS NOT NULL
			ORDER BY kcu.CONSTRAINT_NAME`
		args = []interface{}{schema, tableName}
	case DriverOracle:
		query = `
			SELECT
				ac.constraint_name,
				acc.column_name,
				ac_ref.owner AS referenced_schema,
				ac_ref.table_name AS referenced_table,
				acc_ref.column_name AS referenced_column
			FROM all_constraints ac
			JOIN all_cons_columns acc
				ON ac.constraint_name = acc.constraint_name
				AND ac.owner = acc.owner
			JOIN all_constraints ac_ref
				ON ac.r_constraint_name = ac_ref.constraint_name
				AND ac.r_owner = ac_ref.owner
			JOIN all_cons_columns acc_ref
				ON ac_ref.constraint_name = acc_ref.constraint_name
				AND ac_ref.owner = acc_ref.owner
			WHERE ac.constraint_type = 'R'
				AND ac.owner = :1
				AND ac.table_name = :2
			ORDER BY ac.constraint_name`
		args = []interface{}{strings.ToUpper(schema), strings.ToUpper(tableName)}
	case DriverSQLite:
		query = fmt.Sprintf("PRAGMA foreign_key_list(%s)", tableName)
		args = []interface{}{}
	}

	return query, args
}

// GetDatabaseInfoQuery returns query for database info
func (qb *QueryBuilder) GetDatabaseInfoQuery() string {
	switch qb.driver {
	case DriverSQLServer:
		return "SELECT @@VERSION"
	case DriverPostgreSQL:
		return "SELECT version()"
	case DriverMySQL:
		return "SELECT VERSION()"
	case DriverOracle:
		return "SELECT * FROM v$version WHERE banner LIKE 'Oracle%'"
	case DriverSQLite:
		return "SELECT sqlite_version()"
	default:
		return "SELECT VERSION()"
	}
}

// SupportsStoredProcedures returns true if driver supports stored procedures
func (qb *QueryBuilder) SupportsStoredProcedures() bool {
	return qb.driver == DriverSQLServer || qb.driver == DriverPostgreSQL || qb.driver == DriverOracle || qb.driver == DriverMySQL
}

// SupportsFunctions returns true if driver supports functions
func (qb *QueryBuilder) SupportsFunctions() bool {
	return qb.driver == DriverSQLServer || qb.driver == DriverPostgreSQL || qb.driver == DriverOracle || qb.driver == DriverMySQL
}

// SupportsTriggers returns true if driver supports triggers
func (qb *QueryBuilder) SupportsTriggers() bool {
	return true // All supported databases have triggers
}

// SupportsViews returns true if driver supports views
func (qb *QueryBuilder) SupportsViews() bool {
	return true // All supported databases have views
}

// ListProceduresQuery returns the query to list stored procedures
func (qb *QueryBuilder) ListProceduresQuery(schemaFilter, nameFilter string, limit, offset int) (string, []interface{}) {
	var query string
	var args []interface{}
	argIndex := 1

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT
				s.name AS routine_schema,
				o.name AS routine_name,
				o.create_date AS created,
				o.modify_date AS last_altered
			FROM sys.objects o
			INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
			WHERE o.type = 'P' AND o.is_ms_shipped = 0`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND s.name = %s", qb.Placeholder(argIndex))
			args = append(args, schemaFilter)
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND o.name LIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+nameFilter+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY s.name, o.name OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, limit)

	case DriverPostgreSQL:
		query = `
			SELECT
				routine_schema,
				routine_name,
				created::timestamp AS created,
				created::timestamp AS last_altered
			FROM information_schema.routines
			WHERE routine_type = 'PROCEDURE'
				AND routine_schema NOT IN ('pg_catalog', 'information_schema')`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND routine_schema = %s", qb.Placeholder(argIndex))
			args = append(args, schemaFilter)
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND routine_name ILIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+nameFilter+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY routine_schema, routine_name LIMIT %d OFFSET %d", limit, offset)

	case DriverMySQL:
		query = `
			SELECT
				ROUTINE_SCHEMA as routine_schema,
				ROUTINE_NAME as routine_name,
				CREATED as created,
				LAST_ALTERED as last_altered
			FROM INFORMATION_SCHEMA.ROUTINES
			WHERE ROUTINE_TYPE = 'PROCEDURE'
				AND ROUTINE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')`

		if schemaFilter != "" {
			query += " AND ROUTINE_SCHEMA = ?"
			args = append(args, schemaFilter)
		}

		if nameFilter != "" {
			query += " AND ROUTINE_NAME LIKE ?"
			args = append(args, "%"+nameFilter+"%")
		}

		query += fmt.Sprintf(" ORDER BY ROUTINE_SCHEMA, ROUTINE_NAME LIMIT %d OFFSET %d", limit, offset)

	case DriverOracle:
		query = `
			SELECT
				owner as routine_schema,
				object_name as routine_name,
				created,
				last_ddl_time as last_altered
			FROM all_procedures
			WHERE object_type = 'PROCEDURE'
				AND owner NOT IN ('SYS', 'SYSTEM')`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND owner = %s", qb.Placeholder(argIndex))
			args = append(args, strings.ToUpper(schemaFilter))
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND object_name LIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+strings.ToUpper(nameFilter)+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY owner, object_name OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, limit)

	case DriverSQLite:
		// SQLite doesn't support stored procedures
		return "", nil
	}

	return query, args
}

// GetProcedureCodeQuery returns the query to get procedure source code
func (qb *QueryBuilder) GetProcedureCodeQuery(schema, procedureName string) (string, []interface{}) {
	var query string
	var args []interface{}

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT m.definition
			FROM sys.sql_modules m
			INNER JOIN sys.objects o ON m.object_id = o.object_id
			INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
			WHERE o.type = 'P' AND s.name = @p1 AND o.name = @p2`
		args = []interface{}{schema, procedureName}

	case DriverPostgreSQL:
		query = `
			SELECT pg_get_functiondef(p.oid)
			FROM pg_proc p
			JOIN pg_namespace n ON p.pronamespace = n.oid
			WHERE n.nspname = $1 AND p.proname = $2 AND prokind = 'p'`
		args = []interface{}{schema, procedureName}

	case DriverMySQL:
		query = `
			SELECT ROUTINE_DEFINITION
			FROM INFORMATION_SCHEMA.ROUTINES
			WHERE ROUTINE_SCHEMA = ? AND ROUTINE_NAME = ? AND ROUTINE_TYPE = 'PROCEDURE'`
		args = []interface{}{schema, procedureName}

	case DriverOracle:
		query = `
			SELECT text
			FROM all_source
			WHERE owner = :1 AND name = :2 AND type = 'PROCEDURE'
			ORDER BY line`
		args = []interface{}{strings.ToUpper(schema), strings.ToUpper(procedureName)}
	}

	return query, args
}

// ListViewsQuery returns the query to list views
func (qb *QueryBuilder) ListViewsQuery(schemaFilter, nameFilter string, limit, offset int) (string, []interface{}) {
	var query string
	var args []interface{}
	argIndex := 1

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT
				s.name AS view_schema,
				v.name AS view_name,
				v.create_date AS created,
				v.modify_date AS last_altered
			FROM sys.views v
			INNER JOIN sys.schemas s ON v.schema_id = s.schema_id
			WHERE v.is_ms_shipped = 0`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND s.name = %s", qb.Placeholder(argIndex))
			args = append(args, schemaFilter)
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND v.name LIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+nameFilter+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY s.name, v.name OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, limit)

	case DriverPostgreSQL:
		query = `
			SELECT
				table_schema as view_schema,
				table_name as view_name,
				NULL::timestamp as created,
				NULL::timestamp as last_altered
			FROM information_schema.views
			WHERE table_schema NOT IN ('pg_catalog', 'information_schema')`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND table_schema = %s", qb.Placeholder(argIndex))
			args = append(args, schemaFilter)
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND table_name ILIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+nameFilter+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY table_schema, table_name LIMIT %d OFFSET %d", limit, offset)

	case DriverMySQL:
		query = `
			SELECT
				TABLE_SCHEMA as view_schema,
				TABLE_NAME as view_name,
				NULL as created,
				NULL as last_altered
			FROM INFORMATION_SCHEMA.VIEWS
			WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')`

		if schemaFilter != "" {
			query += " AND TABLE_SCHEMA = ?"
			args = append(args, schemaFilter)
		}

		if nameFilter != "" {
			query += " AND TABLE_NAME LIKE ?"
			args = append(args, "%"+nameFilter+"%")
		}

		query += fmt.Sprintf(" ORDER BY TABLE_SCHEMA, TABLE_NAME LIMIT %d OFFSET %d", limit, offset)

	case DriverOracle:
		query = `
			SELECT
				owner as view_schema,
				view_name,
				NULL as created,
				NULL as last_altered
			FROM all_views
			WHERE owner NOT IN ('SYS', 'SYSTEM')`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND owner = %s", qb.Placeholder(argIndex))
			args = append(args, strings.ToUpper(schemaFilter))
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND view_name LIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+strings.ToUpper(nameFilter)+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY owner, view_name OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, limit)

	case DriverSQLite:
		query = `
			SELECT
				'main' as view_schema,
				name as view_name,
				NULL as created,
				NULL as last_altered
			FROM sqlite_master
			WHERE type = 'view'`

		if nameFilter != "" {
			query += " AND name LIKE ?"
			args = append(args, "%"+nameFilter+"%")
		}

		query += fmt.Sprintf(" ORDER BY name LIMIT %d OFFSET %d", limit, offset)
	}

	return query, args
}

// GetViewDefinitionQuery returns the query to get view definition
func (qb *QueryBuilder) GetViewDefinitionQuery(schema, viewName string) (string, []interface{}) {
	var query string
	var args []interface{}

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT m.definition
			FROM sys.sql_modules m
			INNER JOIN sys.views v ON m.object_id = v.object_id
			INNER JOIN sys.schemas s ON v.schema_id = s.schema_id
			WHERE s.name = @p1 AND v.name = @p2`
		args = []interface{}{schema, viewName}

	case DriverPostgreSQL:
		query = `
			SELECT view_definition
			FROM information_schema.views
			WHERE table_schema = $1 AND table_name = $2`
		args = []interface{}{schema, viewName}

	case DriverMySQL:
		query = `
			SELECT VIEW_DEFINITION
			FROM INFORMATION_SCHEMA.VIEWS
			WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?`
		args = []interface{}{schema, viewName}

	case DriverOracle:
		query = `
			SELECT text
			FROM all_views
			WHERE owner = :1 AND view_name = :2`
		args = []interface{}{strings.ToUpper(schema), strings.ToUpper(viewName)}

	case DriverSQLite:
		query = `
			SELECT sql
			FROM sqlite_master
			WHERE type = 'view' AND name = ?`
		args = []interface{}{viewName}
	}

	return query, args
}

// ListFunctionsQuery returns the query to list functions
func (qb *QueryBuilder) ListFunctionsQuery(schemaFilter, nameFilter, funcType string, limit, offset int) (string, []interface{}) {
	var query string
	var args []interface{}
	argIndex := 1

	switch qb.driver {
	case DriverSQLServer:
		typeFilter := ""
		switch funcType {
		case "scalar":
			typeFilter = " AND o.type = 'FN'"
		case "table":
			typeFilter = " AND o.type IN ('IF', 'TF')"
		default:
			typeFilter = " AND o.type IN ('FN', 'IF', 'TF')"
		}

		query = `
			SELECT
				s.name AS routine_schema,
				o.name AS routine_name,
				o.type_desc AS function_type,
				o.create_date AS created,
				o.modify_date AS last_altered
			FROM sys.objects o
			INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
			WHERE o.is_ms_shipped = 0` + typeFilter

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND s.name = %s", qb.Placeholder(argIndex))
			args = append(args, schemaFilter)
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND o.name LIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+nameFilter+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY s.name, o.name OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, limit)

	case DriverPostgreSQL:
		query = `
			SELECT
				n.nspname AS routine_schema,
				p.proname AS routine_name,
				CASE WHEN p.proretset THEN 'TABLE' ELSE 'SCALAR' END AS function_type,
				NULL::timestamp AS created,
				NULL::timestamp AS last_altered
			FROM pg_proc p
			JOIN pg_namespace n ON p.pronamespace = n.oid
			WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
				AND prokind = 'f'`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND n.nspname = %s", qb.Placeholder(argIndex))
			args = append(args, schemaFilter)
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND p.proname ILIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+nameFilter+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY n.nspname, p.proname LIMIT %d OFFSET %d", limit, offset)

	case DriverMySQL:
		query = `
			SELECT
				ROUTINE_SCHEMA as routine_schema,
				ROUTINE_NAME as routine_name,
				'FUNCTION' as function_type,
				CREATED as created,
				LAST_ALTERED as last_altered
			FROM INFORMATION_SCHEMA.ROUTINES
			WHERE ROUTINE_TYPE = 'FUNCTION'
				AND ROUTINE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')`

		if schemaFilter != "" {
			query += " AND ROUTINE_SCHEMA = ?"
			args = append(args, schemaFilter)
		}

		if nameFilter != "" {
			query += " AND ROUTINE_NAME LIKE ?"
			args = append(args, "%"+nameFilter+"%")
		}

		query += fmt.Sprintf(" ORDER BY ROUTINE_SCHEMA, ROUTINE_NAME LIMIT %d OFFSET %d", limit, offset)

	case DriverOracle:
		query = `
			SELECT
				owner as routine_schema,
				object_name as routine_name,
				'FUNCTION' as function_type,
				created,
				last_ddl_time as last_altered
			FROM all_objects
			WHERE object_type = 'FUNCTION'
				AND owner NOT IN ('SYS', 'SYSTEM')`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND owner = %s", qb.Placeholder(argIndex))
			args = append(args, strings.ToUpper(schemaFilter))
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND object_name LIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+strings.ToUpper(nameFilter)+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY owner, object_name OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, limit)

	case DriverSQLite:
		// SQLite doesn't support user-defined functions in system tables
		return "", nil
	}

	return query, args
}

// GetFunctionCodeQuery returns the query to get function source code
func (qb *QueryBuilder) GetFunctionCodeQuery(schema, functionName string) (string, []interface{}) {
	var query string
	var args []interface{}

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT m.definition
			FROM sys.sql_modules m
			INNER JOIN sys.objects o ON m.object_id = o.object_id
			INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
			WHERE o.type IN ('FN', 'IF', 'TF') AND s.name = @p1 AND o.name = @p2`
		args = []interface{}{schema, functionName}

	case DriverPostgreSQL:
		query = `
			SELECT pg_get_functiondef(p.oid)
			FROM pg_proc p
			JOIN pg_namespace n ON p.pronamespace = n.oid
			WHERE n.nspname = $1 AND p.proname = $2 AND prokind = 'f'`
		args = []interface{}{schema, functionName}

	case DriverMySQL:
		query = `
			SELECT ROUTINE_DEFINITION
			FROM INFORMATION_SCHEMA.ROUTINES
			WHERE ROUTINE_SCHEMA = ? AND ROUTINE_NAME = ? AND ROUTINE_TYPE = 'FUNCTION'`
		args = []interface{}{schema, functionName}

	case DriverOracle:
		query = `
			SELECT text
			FROM all_source
			WHERE owner = :1 AND name = :2 AND type = 'FUNCTION'
			ORDER BY line`
		args = []interface{}{strings.ToUpper(schema), strings.ToUpper(functionName)}
	}

	return query, args
}

// ListTriggersQuery returns the query to list triggers
func (qb *QueryBuilder) ListTriggersQuery(schemaFilter, tableName, nameFilter string, includeDisabled bool, limit, offset int) (string, []interface{}) {
	var query string
	var args []interface{}
	argIndex := 1

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT
				s.name AS schema_name,
				t.name AS trigger_name,
				OBJECT_NAME(tr.parent_id) AS table_name,
				tr.is_disabled,
				tr.create_date,
				tr.modify_date
			FROM sys.triggers tr
			INNER JOIN sys.objects t ON tr.object_id = t.object_id
			INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
			WHERE 1=1`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND s.name = %s", qb.Placeholder(argIndex))
			args = append(args, schemaFilter)
			argIndex++
		}

		if tableName != "" {
			query += fmt.Sprintf(" AND OBJECT_NAME(tr.parent_id) = %s", qb.Placeholder(argIndex))
			args = append(args, tableName)
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND t.name LIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+nameFilter+"%")
			argIndex++
		}

		if !includeDisabled {
			query += " AND tr.is_disabled = 0"
		}

		query += fmt.Sprintf(" ORDER BY s.name, OBJECT_NAME(tr.parent_id), t.name OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, limit)

	case DriverPostgreSQL:
		query = `
			SELECT
				n.nspname AS schema_name,
				t.tgname AS trigger_name,
				c.relname AS table_name,
				NOT t.tgenabled AS is_disabled,
				NULL::timestamp AS create_date,
				NULL::timestamp AS modify_date
			FROM pg_trigger t
			JOIN pg_class c ON t.tgrelid = c.oid
			JOIN pg_namespace n ON c.relnamespace = n.oid
			WHERE NOT t.tgisinternal
				AND n.nspname NOT IN ('pg_catalog', 'information_schema')`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND n.nspname = %s", qb.Placeholder(argIndex))
			args = append(args, schemaFilter)
			argIndex++
		}

		if tableName != "" {
			query += fmt.Sprintf(" AND c.relname = %s", qb.Placeholder(argIndex))
			args = append(args, tableName)
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND t.tgname ILIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+nameFilter+"%")
			argIndex++
		}

		query += fmt.Sprintf(" ORDER BY n.nspname, c.relname, t.tgname LIMIT %d OFFSET %d", limit, offset)

	case DriverMySQL:
		query = `
			SELECT
				TRIGGER_SCHEMA as schema_name,
				TRIGGER_NAME as trigger_name,
				EVENT_OBJECT_TABLE as table_name,
				0 as is_disabled,
				CREATED as create_date,
				NULL as modify_date
			FROM INFORMATION_SCHEMA.TRIGGERS
			WHERE TRIGGER_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')`

		if schemaFilter != "" {
			query += " AND TRIGGER_SCHEMA = ?"
			args = append(args, schemaFilter)
		}

		if tableName != "" {
			query += " AND EVENT_OBJECT_TABLE = ?"
			args = append(args, tableName)
		}

		if nameFilter != "" {
			query += " AND TRIGGER_NAME LIKE ?"
			args = append(args, "%"+nameFilter+"%")
		}

		query += fmt.Sprintf(" ORDER BY TRIGGER_SCHEMA, EVENT_OBJECT_TABLE, TRIGGER_NAME LIMIT %d OFFSET %d", limit, offset)

	case DriverOracle:
		query = `
			SELECT
				owner as schema_name,
				trigger_name,
				table_name,
				CASE WHEN status = 'DISABLED' THEN 1 ELSE 0 END as is_disabled,
				NULL as create_date,
				NULL as modify_date
			FROM all_triggers
			WHERE owner NOT IN ('SYS', 'SYSTEM')`

		if schemaFilter != "" {
			query += fmt.Sprintf(" AND owner = %s", qb.Placeholder(argIndex))
			args = append(args, strings.ToUpper(schemaFilter))
			argIndex++
		}

		if tableName != "" {
			query += fmt.Sprintf(" AND table_name = %s", qb.Placeholder(argIndex))
			args = append(args, strings.ToUpper(tableName))
			argIndex++
		}

		if nameFilter != "" {
			query += fmt.Sprintf(" AND trigger_name LIKE %s", qb.Placeholder(argIndex))
			args = append(args, "%"+strings.ToUpper(nameFilter)+"%")
			argIndex++
		}

		if !includeDisabled {
			query += " AND status = 'ENABLED'"
		}

		query += fmt.Sprintf(" ORDER BY owner, table_name, trigger_name OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", offset, limit)

	case DriverSQLite:
		query = `
			SELECT
				'main' as schema_name,
				name as trigger_name,
				tbl_name as table_name,
				0 as is_disabled,
				NULL as create_date,
				NULL as modify_date
			FROM sqlite_master
			WHERE type = 'trigger'`

		if tableName != "" {
			query += " AND tbl_name = ?"
			args = append(args, tableName)
		}

		if nameFilter != "" {
			query += " AND name LIKE ?"
			args = append(args, "%"+nameFilter+"%")
		}

		query += fmt.Sprintf(" ORDER BY tbl_name, name LIMIT %d OFFSET %d", limit, offset)
	}

	return query, args
}

// GetTriggerCodeQuery returns the query to get trigger source code
func (qb *QueryBuilder) GetTriggerCodeQuery(schema, triggerName string) (string, []interface{}) {
	var query string
	var args []interface{}

	switch qb.driver {
	case DriverSQLServer:
		query = `
			SELECT m.definition
			FROM sys.sql_modules m
			INNER JOIN sys.triggers tr ON m.object_id = tr.object_id
			INNER JOIN sys.objects t ON tr.object_id = t.object_id
			INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
			WHERE s.name = @p1 AND t.name = @p2`
		args = []interface{}{schema, triggerName}

	case DriverPostgreSQL:
		query = `
			SELECT pg_get_triggerdef(t.oid)
			FROM pg_trigger t
			JOIN pg_class c ON t.tgrelid = c.oid
			JOIN pg_namespace n ON c.relnamespace = n.oid
			WHERE n.nspname = $1 AND t.tgname = $2`
		args = []interface{}{schema, triggerName}

	case DriverMySQL:
		query = `
			SELECT ACTION_STATEMENT
			FROM INFORMATION_SCHEMA.TRIGGERS
			WHERE TRIGGER_SCHEMA = ? AND TRIGGER_NAME = ?`
		args = []interface{}{schema, triggerName}

	case DriverOracle:
		query = `
			SELECT trigger_body
			FROM all_triggers
			WHERE owner = :1 AND trigger_name = :2`
		args = []interface{}{strings.ToUpper(schema), strings.ToUpper(triggerName)}

	case DriverSQLite:
		query = `
			SELECT sql
			FROM sqlite_master
			WHERE type = 'trigger' AND name = ?`
		args = []interface{}{triggerName}
	}

	return query, args
}

// SearchObjectsQuery returns the query to search database objects
func (qb *QueryBuilder) SearchObjectsQuery(searchTerm string, searchInCode bool, objectTypes []string) (string, []interface{}) {
	var query string
	var args []interface{}

	switch qb.driver {
	case DriverSQLServer:
		// SQL Server type map
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

		query = fmt.Sprintf(`
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
			  AND (
				  o.name LIKE '%%' + @p1 + '%%'
				  %s
			  )
			ORDER BY s.name, o.name`, typeInClause, searchInCodeClause)
		args = []interface{}{searchTerm}

	case DriverPostgreSQL:
		objectTypeFilter := ""
		if len(objectTypes) > 0 {
			var types []string
			for _, ot := range objectTypes {
				switch ot {
				case "table":
					types = append(types, "'BASE TABLE'")
				case "view":
					types = append(types, "'VIEW'")
				case "procedure", "function":
					types = append(types, "'ROUTINE'")
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

		query = fmt.Sprintf(`
			SELECT
				table_schema AS schema_name,
				table_name AS object_name,
				table_type AS object_type,
				NULL AS create_date,
				NULL AS modify_date,
				CASE WHEN view_definition IS NOT NULL THEN 1 ELSE 0 END AS has_code
			FROM information_schema.tables
			WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
			  AND (table_name LIKE '%%' || $1 || '%%' %s)
			  %s
			ORDER BY table_schema, table_name`, searchInCodeClause, objectTypeFilter)
		args = []interface{}{searchTerm}

	case DriverMySQL:
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

		query = fmt.Sprintf(`
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
		args = []interface{}{searchTerm}

	case DriverOracle:
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

		query = fmt.Sprintf(`
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
		args = []interface{}{strings.ToUpper(searchTerm)}

	case DriverSQLite:
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

		query = fmt.Sprintf(`
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
			args = []interface{}{searchTerm, searchTerm}
		} else {
			args = []interface{}{searchTerm}
		}
	}

	return query, args
}

// GetDatabaseDetailsQuery returns query for detailed database information (SQL Server specific)
func (qb *QueryBuilder) GetDatabaseDetailsQuery() (string, bool) {
	switch qb.driver {
	case DriverSQLServer:
		return `
			SELECT
				DB_NAME() AS database_name,
				collation_name,
				recovery_model_desc,
				compatibility_level,
				create_date
			FROM sys.databases
			WHERE name = DB_NAME()`, true
	case DriverPostgreSQL:
		return `
			SELECT
				current_database() AS database_name,
				pg_encoding_to_char(encoding) AS encoding,
				datcollate AS collation,
				'' AS recovery_model_desc,
				0 AS compatibility_level,
				NULL AS create_date
			FROM pg_database
			WHERE datname = current_database()`, true
	case DriverMySQL:
		return `
			SELECT
				DATABASE() AS database_name,
				DEFAULT_COLLATION_NAME AS collation_name,
				'' AS recovery_model_desc,
				0 AS compatibility_level,
				NULL AS create_date
			FROM INFORMATION_SCHEMA.SCHEMATA
			WHERE SCHEMA_NAME = DATABASE()`, true
	default:
		// Oracle and SQLite don't have equivalent detailed metadata
		return "", false
	}
}

// GetObjectCountsQuery returns query to count database objects
func (qb *QueryBuilder) GetObjectCountsQuery() (string, bool) {
	switch qb.driver {
	case DriverSQLServer:
		return `
			SELECT
				COUNT(CASE WHEN type = 'U' THEN 1 END) AS tables,
				COUNT(CASE WHEN type = 'V' THEN 1 END) AS views,
				COUNT(CASE WHEN type = 'P' THEN 1 END) AS procedures,
				COUNT(CASE WHEN type IN ('FN', 'IF', 'TF') THEN 1 END) AS functions,
				COUNT(CASE WHEN type = 'TR' THEN 1 END) AS triggers
			FROM sys.objects
			WHERE is_ms_shipped = 0`, true

	case DriverPostgreSQL:
		return `
			SELECT
				COUNT(CASE WHEN table_type = 'BASE TABLE' THEN 1 END) AS tables,
				COUNT(CASE WHEN table_type = 'VIEW' THEN 1 END) AS views,
				(SELECT COUNT(*) FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND prokind = 'p') AS procedures,
				(SELECT COUNT(*) FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND prokind = 'f') AS functions,
				(SELECT COUNT(*) FROM pg_trigger t JOIN pg_class c ON t.tgrelid = c.oid JOIN pg_namespace n ON c.relnamespace = n.oid WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND NOT tgisinternal) AS triggers
			FROM information_schema.tables
			WHERE table_schema NOT IN ('pg_catalog', 'information_schema')`, true

	case DriverMySQL:
		return `
			SELECT
				SUM(CASE WHEN TABLE_TYPE = 'BASE TABLE' THEN 1 ELSE 0 END) AS tables,
				SUM(CASE WHEN TABLE_TYPE = 'VIEW' THEN 1 ELSE 0 END) AS views,
				(SELECT COUNT(*) FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_TYPE = 'PROCEDURE' AND ROUTINE_SCHEMA = DATABASE()) AS procedures,
				(SELECT COUNT(*) FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_TYPE = 'FUNCTION' AND ROUTINE_SCHEMA = DATABASE()) AS functions,
				(SELECT COUNT(*) FROM INFORMATION_SCHEMA.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE()) AS triggers
			FROM INFORMATION_SCHEMA.TABLES
			WHERE TABLE_SCHEMA = DATABASE()`, true

	case DriverOracle:
		return `
			SELECT
				COUNT(CASE WHEN object_type = 'TABLE' THEN 1 END) AS tables,
				COUNT(CASE WHEN object_type = 'VIEW' THEN 1 END) AS views,
				COUNT(CASE WHEN object_type = 'PROCEDURE' THEN 1 END) AS procedures,
				COUNT(CASE WHEN object_type = 'FUNCTION' THEN 1 END) AS functions,
				COUNT(CASE WHEN object_type = 'TRIGGER' THEN 1 END) AS triggers
			FROM all_objects
			WHERE owner = USER`, true

	case DriverSQLite:
		return `
			SELECT
				SUM(CASE WHEN type = 'table' THEN 1 ELSE 0 END) AS tables,
				SUM(CASE WHEN type = 'view' THEN 1 ELSE 0 END) AS views,
				0 AS procedures,
				0 AS functions,
				SUM(CASE WHEN type = 'trigger' THEN 1 ELSE 0 END) AS triggers
			FROM sqlite_master
			WHERE name NOT LIKE 'sqlite_%'`, true
	}

	return "", false
}

// GetSchemasListQuery returns query to list database schemas
func (qb *QueryBuilder) GetSchemasListQuery() (string, bool) {
	switch qb.driver {
	case DriverSQLServer:
		return `
			SELECT name
			FROM sys.schemas
			WHERE schema_id < 16384
			ORDER BY name`, true

	case DriverPostgreSQL:
		return `
			SELECT schema_name
			FROM information_schema.schemata
			WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
			ORDER BY schema_name`, true

	case DriverMySQL:
		return `
			SELECT SCHEMA_NAME
			FROM INFORMATION_SCHEMA.SCHEMATA
			WHERE SCHEMA_NAME NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
			ORDER BY SCHEMA_NAME`, true

	case DriverOracle:
		return `
			SELECT username
			FROM all_users
			WHERE username NOT IN ('SYS', 'SYSTEM', 'OUTLN', 'DBSNMP')
			ORDER BY username`, true

	case DriverSQLite:
		// SQLite doesn't have schemas
		return "", false
	}

	return "", false
}
