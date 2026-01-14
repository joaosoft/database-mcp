package mcp

import (
	"database/sql"
	"regexp"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/server"
)

// DbMCPServer is the main struct for the MCP server
type DbMCPServer struct {
	server       *server.MCPServer
	db           *sql.DB
	queryBuilder *QueryBuilder
}

// ConnectionManager handles dynamic database connections
type ConnectionManager struct {
	mu           sync.RWMutex
	connections  map[string]*ConnectionInfo
	activeConnID string
}

// ConnectionInfo stores information about a database connection
type ConnectionInfo struct {
	ID               string    `json:"id"`
	Driver           string    `json:"driver"`
	ConnectionString string    `json:"-"` // Hidden from JSON output
	Name             string    `json:"name"`
	ConnectedAt      time.Time `json:"connected_at"`
	IsActive         bool      `json:"is_active"`
}

var connManager = &ConnectionManager{
	connections: make(map[string]*ConnectionInfo),
}

// Precompiled regexes for performance
var (
	reLineComments             = regexp.MustCompile(`--[^\n]*`)
	reBlockComments            = regexp.MustCompile(`/\*.*?\*/`)
	reMultipleSpaces           = regexp.MustCompile(`\s+`)
	reParensAndCommas          = regexp.MustCompile(`\s*([(),;])\s*`)
	reSingleQuotes             = regexp.MustCompile(`'[^']*'`)
	reDoubleQuotes             = regexp.MustCompile(`"[^"]*"`)
	reSquareBrackets           = regexp.MustCompile(`\[[^\]]*\]`)
	reSelectInto               = regexp.MustCompile(`SELECT\s+.*\s+INTO\s+`)
	reHexPattern               = regexp.MustCompile(`0X[0-9A-F]+`)
	reCharNCharPattern         = regexp.MustCompile(`(CHAR|NCHAR)\s*\(`)
	reValidIdentifier          = regexp.MustCompile(`^[a-zA-Z0-9_#@$]+$`)
	reValidIdentifierBracketed = regexp.MustCompile(`^[a-zA-Z0-9_#@$*\- ]+$`) // Allows more chars inside brackets
)

// Supported database drivers
type DriverType string

// QueryBuilder is defined in query_builder.go with dialect support

// SQLValidator structure for SQL analysis
type SQLValidator struct {
	query      string
	normalized string
}

// SelectQueryParams holds parameters for building a SELECT query
type SelectQueryParams struct {
	Schema         string
	Table          string
	Columns        []string
	WhereClause    string
	OrderBy        string
	OrderDirection string
	Limit          int
	Offset         int
}

// PaginationParams holds pagination parameters
type PaginationParams struct {
	Page     int
	PageSize int
	Offset   int
}
