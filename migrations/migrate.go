package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

var (
	ErrDatabaseRequired = errors.New("migrations: database is required")
	ErrChecksumMismatch = errors.New("migrations: checksum mismatch")
)

//go:embed *.sql
var migrationFiles embed.FS

// Apply installs every embedded SQL migration exactly once. A PostgreSQL
// advisory lock serializes concurrent application instances during rollout.
func Apply(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return ErrDatabaseRequired
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrations: acquire connection: %w", err)
	}
	defer conn.Close()

	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtext('cargoos:pds:migrations'))`); err != nil {
		return fmt.Errorf("migrations: acquire advisory lock: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtext('cargoos:pds:migrations'))`)
	}()

	if _, err = conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS cargoos_schema_migrations (
			version TEXT PRIMARY KEY,
			checksum TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("migrations: create metadata table: %w", err)
	}

	names, err := embeddedMigrationNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		if err = applyOne(ctx, conn, name); err != nil {
			return err
		}
	}
	return nil
}

func embeddedMigrationNames() ([]string, error) {
	entries, err := fs.ReadDir(migrationFiles, ".")
	if err != nil {
		return nil, fmt.Errorf("migrations: list embedded files: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func applyOne(ctx context.Context, conn *sql.Conn, name string) error {
	contents, err := migrationFiles.ReadFile(name)
	if err != nil {
		return fmt.Errorf("migrations: read %s: %w", name, err)
	}
	checksum := fmt.Sprintf("%x", sha256.Sum256(contents))

	var installedChecksum string
	err = conn.QueryRowContext(ctx,
		`SELECT checksum FROM cargoos_schema_migrations WHERE version = $1`, name,
	).Scan(&installedChecksum)
	switch {
	case err == nil && installedChecksum == checksum:
		return nil
	case err == nil:
		return fmt.Errorf("%w: %s", ErrChecksumMismatch, name)
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("migrations: inspect %s: %w", name, err)
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrations: begin %s: %w", name, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, withoutTransactionWrapper(string(contents))); err != nil {
		return fmt.Errorf("migrations: apply %s: %w", name, err)
	}
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO cargoos_schema_migrations (version, checksum) VALUES ($1, $2)`,
		name, checksum,
	); err != nil {
		return fmt.Errorf("migrations: record %s: %w", name, err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("migrations: commit %s: %w", name, err)
	}
	return nil
}

func withoutTransactionWrapper(contents string) string {
	lines := strings.Split(strings.TrimSpace(contents), "\n")
	if len(lines) >= 2 && strings.EqualFold(strings.TrimSpace(lines[0]), "BEGIN;") &&
		strings.EqualFold(strings.TrimSpace(lines[len(lines)-1]), "COMMIT;") {
		lines = lines[1 : len(lines)-1]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
