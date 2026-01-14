package mcp

import (
	"fmt"
	"strings"
)

// OracleDialect implements Dialect for Oracle Database
type OracleDialect struct {
	BaseDialect
}

// NewOracleDialect creates a new Oracle dialect
func NewOracleDialect() *OracleDialect {
	return &OracleDialect{
		BaseDialect: BaseDialect{driver: DriverOracle},
	}
}

// Placeholder returns :1, :2, etc.
func (d *OracleDialect) Placeholder(index int) string {
	return fmt.Sprintf(":%d", index)
}

// QuoteIdentifier returns "NAME" (uppercase)
func (d *OracleDialect) QuoteIdentifier(name string) string {
	return fmt.Sprintf(`"%s"`, strings.ToUpper(name))
}

// PaginationClause returns OFFSET/FETCH syntax (Oracle 12c+)
// Oracle requires ORDER BY before OFFSET/FETCH, uses NULL if not provided
func (d *OracleDialect) PaginationClause(limit, offset int, orderBy string) string {
	if orderBy == "" {
		orderBy = "NULL"
	}
	return fmt.Sprintf("ORDER BY %s OFFSET %d ROWS FETCH NEXT %d ROWS ONLY", orderBy, offset, limit)
}

// ConcatOperator returns || concatenation
func (d *OracleDialect) ConcatOperator(parts ...string) string {
	return strings.Join(parts, " || ")
}

// CurrentDatabase returns SYS_CONTEXT
func (d *OracleDialect) CurrentDatabase() string {
	return "SYS_CONTEXT('USERENV', 'DB_NAME')"
}

// SystemSchemas returns Oracle system schemas
func (d *OracleDialect) SystemSchemas() []string {
	return []string{"SYS", "SYSTEM", "OUTLN", "XDB", "WMSYS", "CTXSYS", "MDSYS", "OLAPSYS"}
}

// NormalizeIdentifier converts to uppercase for Oracle, strips brackets if present
func (d *OracleDialect) NormalizeIdentifier(name string) string {
	// Remove SQL Server style brackets [name] if present
	if len(name) >= 2 && name[0] == '[' && name[len(name)-1] == ']' {
		name = name[1 : len(name)-1]
	}
	return strings.ToUpper(name)
}

// TableMetadata returns Oracle table metadata queries
func (d *OracleDialect) TableMetadata() TableMetadataSQL {
	return TableMetadataSQL{
		ListTables: `
			SELECT
				owner as table_schema,
				table_name,
				'BASE TABLE' as table_type
			FROM all_tables
			WHERE owner NOT IN ('SYS', 'SYSTEM', 'OUTLN', 'XDB', 'WMSYS', 'CTXSYS', 'MDSYS', 'OLAPSYS')`,
		SchemaFilter: " AND owner = %s",
		NameFilter:   " AND table_name LIKE %s",
		OrderBy:      " ORDER BY owner, table_name",

		DescribeTable: `
			SELECT
				column_name,
				data_type,
				nullable as is_nullable,
				data_default as column_default,
				data_length as character_maximum_length
			FROM all_tab_columns
			WHERE owner = :1 AND table_name = :2
			ORDER BY column_id`,

		TableExists: `SELECT COUNT(*) FROM all_tables WHERE owner = :1 AND table_name = :2`,

		GetColumns: `
			SELECT
				column_name,
				data_type,
				data_length,
				nullable,
				data_default
			FROM all_tab_columns
			WHERE owner = :1 AND table_name = :2
			ORDER BY column_id`,

		GetFullSchema: `
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
			ORDER BY c.column_id`,

		GetPrimaryKey: `
			SELECT acc.column_name
			FROM all_constraints ac
			JOIN all_cons_columns acc
				ON ac.constraint_name = acc.constraint_name
				AND ac.owner = acc.owner
			WHERE ac.constraint_type = 'P'
				AND ac.owner = :1
				AND ac.table_name = :2
			ORDER BY acc.position`,

		GetIndexes: `
			SELECT
				i.index_name,
				i.index_type,
				i.uniqueness,
				ic.column_name
			FROM all_indexes i
			JOIN all_ind_columns ic ON i.index_name = ic.index_name AND i.owner = ic.index_owner
			WHERE i.owner = :1 AND i.table_name = :2
			ORDER BY i.index_name, ic.column_position`,

		GetForeignKeys: `
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
			ORDER BY ac.constraint_name`,
	}
}

// ProcedureMetadata returns Oracle procedure metadata queries
func (d *OracleDialect) ProcedureMetadata() ProcedureMetadataSQL {
	return ProcedureMetadataSQL{
		ListProcedures: `
			SELECT
				owner as routine_schema,
				object_name as routine_name,
				created,
				last_ddl_time as last_altered
			FROM all_procedures
			WHERE object_type = 'PROCEDURE'
				AND owner NOT IN ('SYS', 'SYSTEM')`,
		SchemaFilter: " AND owner = %s",
		NameFilter:   " AND object_name LIKE %s",
		OrderBy:      " ORDER BY owner, object_name",

		GetCode: `
			SELECT text
			FROM all_source
			WHERE owner = :1 AND name = :2 AND type = 'PROCEDURE'
			ORDER BY line`,
	}
}

// FunctionMetadata returns Oracle function metadata queries
func (d *OracleDialect) FunctionMetadata() FunctionMetadataSQL {
	return FunctionMetadataSQL{
		ListFunctions: `
			SELECT
				owner as routine_schema,
				object_name as routine_name,
				'FUNCTION' as function_type,
				created,
				last_ddl_time as last_altered
			FROM all_objects
			WHERE object_type = 'FUNCTION'
				AND owner NOT IN ('SYS', 'SYSTEM')`,
		TypeFilterScalar: "",
		TypeFilterTable:  "",
		TypeFilterAll:    "",
		SchemaFilter:     " AND owner = %s",
		NameFilter:       " AND object_name LIKE %s",
		OrderBy:          " ORDER BY owner, object_name",

		GetCode: `
			SELECT text
			FROM all_source
			WHERE owner = :1 AND name = :2 AND type = 'FUNCTION'
			ORDER BY line`,
	}
}

// ViewMetadata returns Oracle view metadata queries
func (d *OracleDialect) ViewMetadata() ViewMetadataSQL {
	return ViewMetadataSQL{
		ListViews: `
			SELECT
				owner as view_schema,
				view_name,
				NULL as created,
				NULL as last_altered
			FROM all_views
			WHERE owner NOT IN ('SYS', 'SYSTEM')`,
		SchemaFilter: " AND owner = %s",
		NameFilter:   " AND view_name LIKE %s",
		OrderBy:      " ORDER BY owner, view_name",

		GetDefinition: `
			SELECT text
			FROM all_views
			WHERE owner = :1 AND view_name = :2`,
	}
}

// TriggerMetadata returns Oracle trigger metadata queries
func (d *OracleDialect) TriggerMetadata() TriggerMetadataSQL {
	return TriggerMetadataSQL{
		ListTriggers: `
			SELECT
				owner as schema_name,
				trigger_name,
				table_name,
				CASE WHEN status = 'DISABLED' THEN 1 ELSE 0 END as is_disabled,
				NULL as create_date,
				NULL as modify_date
			FROM all_triggers
			WHERE owner NOT IN ('SYS', 'SYSTEM')`,
		SchemaFilter:   " AND owner = %s",
		TableFilter:    " AND table_name = %s",
		NameFilter:     " AND trigger_name LIKE %s",
		DisabledFilter: " AND status = 'ENABLED'",
		OrderBy:        " ORDER BY owner, table_name, trigger_name",

		GetCode: `
			SELECT trigger_body
			FROM all_triggers
			WHERE owner = :1 AND trigger_name = :2`,
	}
}

// DatabaseInfo returns Oracle database info queries
func (d *OracleDialect) DatabaseInfo() DatabaseInfoSQL {
	return DatabaseInfoSQL{
		Version: "SELECT * FROM v$version WHERE banner LIKE 'Oracle%'",

		Details: "", // Oracle doesn't have simple equivalent

		ObjectCounts: `
			SELECT
				COUNT(CASE WHEN object_type = 'TABLE' THEN 1 END) AS tables,
				COUNT(CASE WHEN object_type = 'VIEW' THEN 1 END) AS views,
				COUNT(CASE WHEN object_type = 'PROCEDURE' THEN 1 END) AS procedures,
				COUNT(CASE WHEN object_type = 'FUNCTION' THEN 1 END) AS functions,
				COUNT(CASE WHEN object_type = 'TRIGGER' THEN 1 END) AS triggers
			FROM all_objects
			WHERE owner = USER`,

		ListSchemas: `
			SELECT username
			FROM all_users
			WHERE username NOT IN ('SYS', 'SYSTEM', 'OUTLN', 'DBSNMP')
			ORDER BY username`,

		SearchObjects: `
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
			ORDER BY owner, object_name`,
	}
}
