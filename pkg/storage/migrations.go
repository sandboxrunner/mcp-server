package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/rs/zerolog/log"
)

// Migration represents a database migration
type Migration struct {
	Version     int       `json:"version"`
	Description string    `json:"description"`
	Up          []string  `json:"up"`   // SQL statements to apply migration
	Down        []string  `json:"down"` // SQL statements to rollback migration
	Checksum    string    `json:"checksum"`
	AppliedAt   time.Time `json:"applied_at,omitempty"`
}

// MigrationStatus represents the status of a migration
type MigrationStatus struct {
	Version     int       `json:"version"`
	Description string    `json:"description"`
	Checksum    string    `json:"checksum"`
	Applied     bool      `json:"applied"`
	AppliedAt   time.Time `json:"applied_at,omitempty"`
}

// Migrator handles database migrations
type Migrator struct {
	store      *SQLiteStore
	migrations []Migration
}

// NewMigrator creates a new migrator instance
func NewMigrator(store *SQLiteStore) *Migrator {
	migrator := &Migrator{
		store:      store,
		migrations: []Migration{},
	}

	// Register all migrations
	migrator.registerMigrations()

	return migrator
}

// registerMigrations registers all available migrations
func (m *Migrator) registerMigrations() {
	// Migration 1: Initial schema (already applied in sqlite_store.go)
	m.migrations = append(m.migrations, Migration{
		Version:     1,
		Description: "Initial schema with sandboxes, file_metadata, metrics, audit_trail tables",
		Up: []string{
			// Schema is already created in initializeSchema
			"SELECT 1", // Placeholder
		},
		Down: []string{
			"DROP TABLE IF EXISTS audit_trail",
			"DROP TABLE IF EXISTS file_chunk_refs",
			"DROP TABLE IF EXISTS file_chunks", 
			"DROP TABLE IF EXISTS metrics",
			"DROP TABLE IF EXISTS file_search_fts",
			"DROP TABLE IF EXISTS file_metadata",
			"DROP TABLE IF EXISTS sandboxes",
			"DROP TABLE IF EXISTS migrations",
		},
	})

	// Migration 2: Add performance indexes
	m.migrations = append(m.migrations, Migration{
		Version:     2,
		Description: "Add performance indexes for common queries",
		Up: []string{
			"CREATE INDEX IF NOT EXISTS idx_sandboxes_container_id ON sandboxes(container_id)",
			"CREATE INDEX IF NOT EXISTS idx_file_metadata_mime_type ON file_metadata(mime_type)",
			"CREATE INDEX IF NOT EXISTS idx_file_metadata_size ON file_metadata(size_bytes)",
			"CREATE INDEX IF NOT EXISTS idx_metrics_labels ON metrics(labels)",
			"CREATE INDEX IF NOT EXISTS idx_audit_trail_user ON audit_trail(user_id)",
		},
		Down: []string{
			"DROP INDEX IF EXISTS idx_audit_trail_user",
			"DROP INDEX IF EXISTS idx_metrics_labels",
			"DROP INDEX IF EXISTS idx_file_metadata_size",
			"DROP INDEX IF EXISTS idx_file_metadata_mime_type",
			"DROP INDEX IF EXISTS idx_sandboxes_container_id",
		},
	})

	// Migration 3: Add sandbox resource tracking
	m.migrations = append(m.migrations, Migration{
		Version:     3,
		Description: "Add resource tracking columns to sandboxes table",
		Up: []string{
			"ALTER TABLE sandboxes ADD COLUMN cpu_usage_seconds REAL DEFAULT 0",
			"ALTER TABLE sandboxes ADD COLUMN memory_usage_bytes INTEGER DEFAULT 0",
			"ALTER TABLE sandboxes ADD COLUMN disk_usage_bytes INTEGER DEFAULT 0",
			"ALTER TABLE sandboxes ADD COLUMN network_rx_bytes INTEGER DEFAULT 0",
			"ALTER TABLE sandboxes ADD COLUMN network_tx_bytes INTEGER DEFAULT 0",
			"ALTER TABLE sandboxes ADD COLUMN last_resource_update TIMESTAMP",
			"CREATE INDEX IF NOT EXISTS idx_sandboxes_resource_update ON sandboxes(last_resource_update)",
		},
		Down: []string{
			"DROP INDEX IF EXISTS idx_sandboxes_resource_update",
			// Note: SQLite doesn't support DROP COLUMN directly
			"CREATE TABLE sandboxes_backup AS SELECT id, container_id, status, working_dir, environment, created_at, updated_at, config, metadata, version, deleted_at, recovery_data FROM sandboxes",
			"DROP TABLE sandboxes",
			"ALTER TABLE sandboxes_backup RENAME TO sandboxes",
		},
	})

	// Migration 4: Add file content caching
	m.migrations = append(m.migrations, Migration{
		Version:     4,
		Description: "Add file content caching table for faster access",
		Up: []string{
			`CREATE TABLE IF NOT EXISTS file_content_cache (
				file_id INTEGER PRIMARY KEY,
				content_hash TEXT NOT NULL,
				content_data BLOB,
				compressed BOOLEAN DEFAULT FALSE,
				cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				access_count INTEGER DEFAULT 0,
				last_accessed TIMESTAMP,
				FOREIGN KEY (file_id) REFERENCES file_metadata(id) ON DELETE CASCADE
			)`,
			"CREATE INDEX IF NOT EXISTS idx_file_content_cache_hash ON file_content_cache(content_hash)",
			"CREATE INDEX IF NOT EXISTS idx_file_content_cache_accessed ON file_content_cache(last_accessed)",
		},
		Down: []string{
			"DROP TABLE IF EXISTS file_content_cache",
		},
	})

	// Migration 5: Add sandbox templates
	m.migrations = append(m.migrations, Migration{
		Version:     5,
		Description: "Add sandbox templates for faster sandbox creation",
		Up: []string{
			`CREATE TABLE IF NOT EXISTS sandbox_templates (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				description TEXT,
				config TEXT NOT NULL, -- JSON configuration
				base_image TEXT NOT NULL,
				pre_installed_packages TEXT, -- JSON array
				environment_vars TEXT, -- JSON object
				resource_limits TEXT, -- JSON object
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				created_by TEXT,
				usage_count INTEGER DEFAULT 0,
				is_default BOOLEAN DEFAULT FALSE,
				tags TEXT -- JSON array for categorization
			)`,
			"CREATE INDEX IF NOT EXISTS idx_sandbox_templates_name ON sandbox_templates(name)",
			"CREATE INDEX IF NOT EXISTS idx_sandbox_templates_usage ON sandbox_templates(usage_count DESC)",
			"CREATE INDEX IF NOT EXISTS idx_sandbox_templates_default ON sandbox_templates(is_default)",
		},
		Down: []string{
			"DROP TABLE IF EXISTS sandbox_templates",
		},
	})

	// Migration 6: Add workflow execution tracking
	m.migrations = append(m.migrations, Migration{
		Version:     6,
		Description: "Add workflow execution tracking for complex operations",
		Up: []string{
			`CREATE TABLE IF NOT EXISTS workflow_executions (
				id TEXT PRIMARY KEY,
				workflow_name TEXT NOT NULL,
				sandbox_id TEXT,
				status TEXT NOT NULL, -- pending, running, completed, failed
				input_data TEXT, -- JSON input parameters
				output_data TEXT, -- JSON output results
				error_message TEXT,
				started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				completed_at TIMESTAMP,
				execution_time_seconds REAL,
				step_count INTEGER DEFAULT 0,
				current_step INTEGER DEFAULT 0,
				metadata TEXT, -- JSON additional metadata
				FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE SET NULL
			)`,
			`CREATE TABLE IF NOT EXISTS workflow_steps (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				execution_id TEXT NOT NULL,
				step_name TEXT NOT NULL,
				step_order INTEGER NOT NULL,
				status TEXT NOT NULL, -- pending, running, completed, failed, skipped
				input_data TEXT, -- JSON
				output_data TEXT, -- JSON
				error_message TEXT,
				started_at TIMESTAMP,
				completed_at TIMESTAMP,
				execution_time_seconds REAL,
				retry_count INTEGER DEFAULT 0,
				FOREIGN KEY (execution_id) REFERENCES workflow_executions(id) ON DELETE CASCADE
			)`,
			"CREATE INDEX IF NOT EXISTS idx_workflow_executions_status ON workflow_executions(status)",
			"CREATE INDEX IF NOT EXISTS idx_workflow_executions_sandbox ON workflow_executions(sandbox_id)",
			"CREATE INDEX IF NOT EXISTS idx_workflow_executions_started ON workflow_executions(started_at)",
			"CREATE INDEX IF NOT EXISTS idx_workflow_steps_execution ON workflow_steps(execution_id)",
			"CREATE INDEX IF NOT EXISTS idx_workflow_steps_status ON workflow_steps(status)",
		},
		Down: []string{
			"DROP TABLE IF EXISTS workflow_steps",
			"DROP TABLE IF EXISTS workflow_executions",
		},
	})

	// Calculate checksums for all migrations
	for i := range m.migrations {
		m.migrations[i].Checksum = m.calculateChecksum(&m.migrations[i])
	}

	// Sort migrations by version to ensure proper order
	sort.Slice(m.migrations, func(i, j int) bool {
		return m.migrations[i].Version < m.migrations[j].Version
	})
}

// calculateChecksum calculates a SHA256 checksum for a migration
func (m *Migrator) calculateChecksum(migration *Migration) string {
	hasher := sha256.New()
	
	// Include version and description
	hasher.Write([]byte(fmt.Sprintf("%d:%s:", migration.Version, migration.Description)))
	
	// Include all up statements
	for _, stmt := range migration.Up {
		hasher.Write([]byte(stmt))
	}
	
	// Include all down statements
	for _, stmt := range migration.Down {
		hasher.Write([]byte(stmt))
	}
	
	return hex.EncodeToString(hasher.Sum(nil))
}

// GetPendingMigrations returns migrations that haven't been applied
func (m *Migrator) GetPendingMigrations(ctx context.Context) ([]Migration, error) {
	appliedVersions, err := m.getAppliedVersions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get applied versions: %w", err)
	}

	var pending []Migration
	for _, migration := range m.migrations {
		if !containsInt(appliedVersions, migration.Version) {
			pending = append(pending, migration)
		}
	}

	return pending, nil
}

// GetAppliedMigrations returns migrations that have been applied
func (m *Migrator) GetAppliedMigrations(ctx context.Context) ([]MigrationStatus, error) {
	query := `
		SELECT version, description, applied_at
		FROM migrations
		ORDER BY version ASC`

	rows, err := m.store.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	var applied []MigrationStatus
	for rows.Next() {
		var status MigrationStatus
		err := rows.Scan(&status.Version, &status.Description, &status.AppliedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan migration status: %w", err)
		}

		status.Applied = true

		// Find corresponding migration for checksum
		for _, migration := range m.migrations {
			if migration.Version == status.Version {
				status.Checksum = migration.Checksum
				break
			}
		}

		applied = append(applied, status)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return applied, nil
}

// Migrate applies all pending migrations
func (m *Migrator) Migrate(ctx context.Context) error {
	log.Info().Msg("Starting database migration")

	pending, err := m.GetPendingMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get pending migrations: %w", err)
	}

	if len(pending) == 0 {
		log.Info().Msg("No pending migrations found")
		return nil
	}

	log.Info().Int("count", len(pending)).Msg("Found pending migrations")

	for _, migration := range pending {
		if err := m.applyMigration(ctx, &migration); err != nil {
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}
		log.Info().
			Int("version", migration.Version).
			Str("description", migration.Description).
			Msg("Migration applied successfully")
	}

	log.Info().Msg("All migrations completed successfully")
	return nil
}

// applyMigration applies a single migration
func (m *Migrator) applyMigration(ctx context.Context, migration *Migration) error {
	tx, err := m.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Execute all up statements
	for i, statement := range migration.Up {
		if statement == "" || statement == "SELECT 1" {
			continue // Skip empty or placeholder statements
		}

		log.Debug().
			Int("version", migration.Version).
			Int("statement", i+1).
			Str("sql", statement).
			Msg("Executing migration statement")

		_, err := tx.Exec(statement)
		if err != nil {
			return fmt.Errorf("failed to execute statement %d: %w", i+1, err)
		}
	}

	// Record migration as applied
	recordQuery := `
		INSERT OR REPLACE INTO migrations (version, description, applied_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)`
	
	_, err = tx.Exec(recordQuery, migration.Version, migration.Description)
	if err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}

	return nil
}

// Rollback rolls back migrations to a target version
func (m *Migrator) Rollback(ctx context.Context, targetVersion int) error {
	log.Info().Int("target_version", targetVersion).Msg("Starting migration rollback")

	appliedVersions, err := m.getAppliedVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied versions: %w", err)
	}

	// Find migrations to rollback (in reverse order)
	var toRollback []Migration
	for i := len(m.migrations) - 1; i >= 0; i-- {
		migration := m.migrations[i]
		if migration.Version > targetVersion && containsInt(appliedVersions, migration.Version) {
			toRollback = append(toRollback, migration)
		}
	}

	if len(toRollback) == 0 {
		log.Info().Msg("No migrations to rollback")
		return nil
	}

	log.Info().Int("count", len(toRollback)).Msg("Found migrations to rollback")

	for _, migration := range toRollback {
		if err := m.rollbackMigration(ctx, &migration); err != nil {
			return fmt.Errorf("failed to rollback migration %d: %w", migration.Version, err)
		}
		log.Info().
			Int("version", migration.Version).
			Str("description", migration.Description).
			Msg("Migration rolled back successfully")
	}

	log.Info().Msg("Rollback completed successfully")
	return nil
}

// rollbackMigration rolls back a single migration
func (m *Migrator) rollbackMigration(ctx context.Context, migration *Migration) error {
	tx, err := m.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Execute all down statements
	for i, statement := range migration.Down {
		if statement == "" {
			continue
		}

		log.Debug().
			Int("version", migration.Version).
			Int("statement", i+1).
			Str("sql", statement).
			Msg("Executing rollback statement")

		_, err := tx.Exec(statement)
		if err != nil {
			return fmt.Errorf("failed to execute rollback statement %d: %w", i+1, err)
		}
	}

	// Remove migration record
	removeQuery := "DELETE FROM migrations WHERE version = ?"
	_, err = tx.Exec(removeQuery, migration.Version)
	if err != nil {
		return fmt.Errorf("failed to remove migration record: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit rollback: %w", err)
	}

	return nil
}

// ValidateMigrations checks if applied migrations match registered ones
func (m *Migrator) ValidateMigrations(ctx context.Context) error {
	log.Info().Msg("Validating migrations")

	applied, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	for _, appliedMigration := range applied {
		// Find the corresponding registered migration
		var found bool
		for _, registeredMigration := range m.migrations {
			if registeredMigration.Version == appliedMigration.Version {
				found = true
				
				// Check if checksums match
				expectedChecksum := registeredMigration.Checksum
				if appliedMigration.Checksum != expectedChecksum {
					return fmt.Errorf("migration %d checksum mismatch: expected %s, got %s",
						appliedMigration.Version, expectedChecksum, appliedMigration.Checksum)
				}
				break
			}
		}

		if !found {
			log.Warn().
				Int("version", appliedMigration.Version).
				Msg("Applied migration not found in registered migrations")
		}
	}

	log.Info().Int("validated_count", len(applied)).Msg("Migration validation completed")
	return nil
}

// GetMigrationStatus returns the current migration status
func (m *Migrator) GetMigrationStatus(ctx context.Context) (*MigrationStatusSummary, error) {
	applied, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get applied migrations: %w", err)
	}

	pending, err := m.GetPendingMigrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending migrations: %w", err)
	}

	var currentVersion int
	if len(applied) > 0 {
		currentVersion = applied[len(applied)-1].Version
	}

	var targetVersion int
	if len(m.migrations) > 0 {
		targetVersion = m.migrations[len(m.migrations)-1].Version
	}

	return &MigrationStatusSummary{
		CurrentVersion:    currentVersion,
		TargetVersion:     targetVersion,
		AppliedCount:      len(applied),
		PendingCount:      len(pending),
		TotalMigrations:   len(m.migrations),
		UpToDate:          len(pending) == 0,
		AppliedMigrations: applied,
		PendingMigrations: pending,
	}, nil
}

// MigrationStatusSummary provides an overview of migration status
type MigrationStatusSummary struct {
	CurrentVersion    int                `json:"current_version"`
	TargetVersion     int                `json:"target_version"`
	AppliedCount      int                `json:"applied_count"`
	PendingCount      int                `json:"pending_count"`
	TotalMigrations   int                `json:"total_migrations"`
	UpToDate          bool               `json:"up_to_date"`
	AppliedMigrations []MigrationStatus  `json:"applied_migrations"`
	PendingMigrations []Migration        `json:"pending_migrations"`
}

// getAppliedVersions returns a slice of applied migration versions
func (m *Migrator) getAppliedVersions(ctx context.Context) ([]int, error) {
	query := "SELECT version FROM migrations ORDER BY version ASC"
	rows, err := m.store.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query applied versions: %w", err)
	}
	defer rows.Close()

	var versions []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("failed to scan version: %w", err)
		}
		versions = append(versions, version)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return versions, nil
}

// containsInt checks if a slice contains an integer
func containsInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// CreateMigration creates a new migration file template
func (m *Migrator) CreateMigration(name string) *Migration {
	nextVersion := 1
	if len(m.migrations) > 0 {
		nextVersion = m.migrations[len(m.migrations)-1].Version + 1
	}

	migration := Migration{
		Version:     nextVersion,
		Description: name,
		Up:          []string{"-- Add your up migration statements here"},
		Down:        []string{"-- Add your down migration statements here"},
	}

	migration.Checksum = m.calculateChecksum(&migration)
	return &migration
}

// Reset drops all tables and reapplies all migrations (DANGEROUS)
func (m *Migrator) Reset(ctx context.Context) error {
	log.Warn().Msg("Resetting database - this will drop all data!")

	tx, err := m.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get all table names
	tablesQuery := `
		SELECT name FROM sqlite_master 
		WHERE type='table' AND name NOT LIKE 'sqlite_%'`
	
	rows, err := tx.Query(tablesQuery)
	if err != nil {
		return fmt.Errorf("failed to get table names: %w", err)
	}

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan table name: %w", err)
		}
		tables = append(tables, tableName)
	}
	rows.Close()

	// Drop all tables
	for _, table := range tables {
		dropQuery := fmt.Sprintf("DROP TABLE IF EXISTS %s", table)
		_, err := tx.Exec(dropQuery)
		if err != nil {
			return fmt.Errorf("failed to drop table %s: %w", table, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit reset: %w", err)
	}

	// Reinitialize schema
	if err := m.store.initializeSchema(); err != nil {
		return fmt.Errorf("failed to reinitialize schema: %w", err)
	}

	// Apply all migrations
	if err := m.Migrate(ctx); err != nil {
		return fmt.Errorf("failed to apply migrations after reset: %w", err)
	}

	log.Info().Msg("Database reset completed successfully")
	return nil
}