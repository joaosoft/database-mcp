package mcp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"
)

// Database connection pool configuration constants
const (
	DBMaxOpenConns    = 25
	DBMaxIdleConns    = 5
	DBConnMaxLifetime = 5 * time.Minute
	DBPingTimeout     = 5 * time.Second
)

func newDbConnection() (*sql.DB, string, error) {
	// Get database driver type (default to sqlserver for backward compatibility)
	driver := os.Getenv("DB_DRIVER")
	if driver == "" {
		driver = "sqlserver"
	}

	// Connection configuration over environment variable
	connString := os.Getenv("DB_CONNECTION_STRING")
	if connString == "" {
		return nil, "", errors.New("DB_CONNECTION_STRING not defined")
	}

	db, err := sql.Open(driver, connString)
	if err != nil {
		return nil, "", errors.New(fmt.Sprintf("Error connecting to database: %v", err))
	}

	// Configure connection pool
	db.SetMaxOpenConns(DBMaxOpenConns)
	db.SetMaxIdleConns(DBMaxIdleConns)
	db.SetConnMaxLifetime(DBConnMaxLifetime)

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), DBPingTimeout)
	defer cancel()

	if err = db.PingContext(ctx); err != nil {
		return nil, "", errors.New(fmt.Sprintf("Error testing connection: %v", err))
	}

	return db, driver, nil
}
