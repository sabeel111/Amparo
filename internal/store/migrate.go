// Package store provides the persistence layer for the SCA platform.
//
// It wraps a Postgres connection (pgx) and ships embedded, versioned SQL
// migrations applied in order. A Store interface abstracts the concrete
// PostgresStore so a future SqliteStore (or test double) can be swapped in
// without touching callers.
package store

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DefaultConnString is the development connection string; overridable via
// DATABASE_URL.
const DefaultConnString = "postgres://sca:sca@localhost:5432/sca?sslmode=disable"

// Open creates a connection pool and runs all pending migrations.
func Open(ctx context.Context, connString string) (*pgxpool.Pool, error) {
	if connString == "" {
		connString = DefaultConnString
	}
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("store: opening pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// Migrate applies all embedded SQL migrations in filename order. Idempotent:
// tracks applied versions in schema_migrations.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("store: creating schema_migrations: %w", err)
	}

	applied, err := appliedMigrations(ctx, pool)
	if err != nil {
		return err
	}

	files, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("store: reading migrations: %w", err)
	}
	// Sort by filename so 001 < 002 < ...
	sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".sql") {
			continue
		}
		if applied[f.Name()] {
			continue
		}
		sql, err := migrationsFS.ReadFile("migrations/" + f.Name())
		if err != nil {
			return fmt.Errorf("store: reading %s: %w", f.Name(), err)
		}
		// Execute the whole migration in one transaction so partial applies
		// don't leave the schema half-migrated.
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("store: begin tx for %s: %w", f.Name(), err)
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: applying %s: %w", f.Name(), err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES($1)", f.Name()); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: recording %s: %w", f.Name(), err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("store: committing %s: %w", f.Name(), err)
		}
	}
	return nil
}

func appliedMigrations(ctx context.Context, pool *pgxpool.Pool) (map[string]bool, error) {
	rows, err := pool.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("store: reading applied migrations: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}
