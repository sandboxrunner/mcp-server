package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

// SQLiteStore provides a SQLite-based storage implementation
type SQLiteStore struct {
	db             *sql.DB
	dbPath         string
	connPool       *ConnectionPool
	migrationVer   int
	backupDir      string
	metrics        *StorageMetrics
	mu             sync.RWMutex
	closed         bool
}

// ConnectionPool manages SQLite connection pooling
type ConnectionPool struct {
	maxOpenConns    int
	maxIdleConns    int
	connMaxLifetime time.Duration
	connMaxIdleTime time.Duration
}

// StorageMetrics tracks storage performance and usage
type StorageMetrics struct {
	QueryCount      int64
	TransactionCount int64
	ErrorCount      int64
	BackupCount     int64
	LastBackup      time.Time
	DatabaseSize    int64
	mu              sync.RWMutex
}

// Transaction represents a database transaction with rollback support
type Transaction struct {
	tx     *sql.Tx
	store  *SQLiteStore
	active bool
	mu     sync.Mutex
}

// Config holds SQLiteStore configuration
type Config struct {
	DatabasePath    string
	BackupDir       string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	EnableBackup    bool
	BackupInterval  time.Duration
}

// DefaultConfig returns default SQLite configuration
func DefaultConfig() *Config {
	return &Config{
		DatabasePath:    "sandbox_runner.db",
		BackupDir:       "backups",
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 10,
		EnableBackup:    true,
		BackupInterval:  time.Hour * 24,
	}
}

// NewSQLiteStore creates a new SQLite storage instance
func NewSQLiteStore(config *Config) (*SQLiteStore, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Ensure database directory exists
	if err := os.MkdirAll(filepath.Dir(config.DatabasePath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Ensure backup directory exists
	if config.EnableBackup {
		if err := os.MkdirAll(config.BackupDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	// Open database with optimized settings
	dsn := fmt.Sprintf("%s?_foreign_keys=on&_journal_mode=WAL&_synchronous=NORMAL&_cache_size=-64000&_temp_store=MEMORY", config.DatabasePath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(config.ConnMaxIdleTime)

	store := &SQLiteStore{
		db:       db,
		dbPath:   config.DatabasePath,
		connPool: &ConnectionPool{
			maxOpenConns:    config.MaxOpenConns,
			maxIdleConns:    config.MaxIdleConns,
			connMaxLifetime: config.ConnMaxLifetime,
			connMaxIdleTime: config.ConnMaxIdleTime,
		},
		backupDir: config.BackupDir,
		metrics:   &StorageMetrics{},
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Initialize database schema
	if err := store.initializeSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Start background backup if enabled
	if config.EnableBackup {
		go store.startBackupScheduler(config.BackupInterval)
	}

	log.Info().
		Str("database_path", config.DatabasePath).
		Int("max_open_conns", config.MaxOpenConns).
		Int("max_idle_conns", config.MaxIdleConns).
		Msg("SQLite store initialized successfully")

	return store, nil
}

// initializeSchema creates all required tables and indexes
func (s *SQLiteStore) initializeSchema() error {
	schema := `
	-- Migrations table to track schema versions
	CREATE TABLE IF NOT EXISTS migrations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		version INTEGER UNIQUE NOT NULL,
		applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		description TEXT
	);

	-- Sandboxes table for sandbox state persistence
	CREATE TABLE IF NOT EXISTS sandboxes (
		id TEXT PRIMARY KEY,
		container_id TEXT,
		status TEXT NOT NULL,
		working_dir TEXT,
		environment TEXT, -- JSON
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		config TEXT, -- JSON
		metadata TEXT, -- JSON
		version INTEGER DEFAULT 1,
		deleted_at TIMESTAMP NULL,
		recovery_data TEXT -- JSON for recovery information
	);

	-- File metadata table for file tracking
	CREATE TABLE IF NOT EXISTS file_metadata (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sandbox_id TEXT NOT NULL,
		file_path TEXT NOT NULL,
		checksum TEXT,
		size_bytes INTEGER,
		mime_type TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		version INTEGER DEFAULT 1,
		parent_file_id INTEGER,
		metadata TEXT, -- JSON for additional metadata
		search_content TEXT, -- For full-text search
		access_count INTEGER DEFAULT 0,
		last_accessed TIMESTAMP,
		deleted_at TIMESTAMP NULL,
		FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE,
		FOREIGN KEY (parent_file_id) REFERENCES file_metadata(id)
	);

	-- Metrics table for time-series storage
	CREATE TABLE IF NOT EXISTS metrics (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		metric_name TEXT NOT NULL,
		metric_type TEXT NOT NULL, -- counter, gauge, histogram
		labels TEXT, -- JSON for labels
		value REAL NOT NULL,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		sandbox_id TEXT,
		aggregation_period TEXT, -- raw, 1m, 5m, 1h, 1d
		FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE
	);

	-- Audit trail table for tracking changes
	CREATE TABLE IF NOT EXISTS audit_trail (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		entity_type TEXT NOT NULL,
		entity_id TEXT NOT NULL,
		action TEXT NOT NULL,
		old_data TEXT, -- JSON
		new_data TEXT, -- JSON
		user_id TEXT,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		metadata TEXT -- JSON for additional context
	);

	-- Storage deduplication table
	CREATE TABLE IF NOT EXISTS file_chunks (
		chunk_hash TEXT PRIMARY KEY,
		data BLOB NOT NULL,
		size_bytes INTEGER NOT NULL,
		ref_count INTEGER DEFAULT 1,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	-- File chunk relationships
	CREATE TABLE IF NOT EXISTS file_chunk_refs (
		file_id INTEGER NOT NULL,
		chunk_hash TEXT NOT NULL,
		chunk_order INTEGER NOT NULL,
		PRIMARY KEY (file_id, chunk_hash, chunk_order),
		FOREIGN KEY (file_id) REFERENCES file_metadata(id) ON DELETE CASCADE,
		FOREIGN KEY (chunk_hash) REFERENCES file_chunks(chunk_hash) ON DELETE CASCADE
	);

	-- Indexes for performance optimization
	CREATE INDEX IF NOT EXISTS idx_sandboxes_status ON sandboxes(status);
	CREATE INDEX IF NOT EXISTS idx_sandboxes_created_at ON sandboxes(created_at);
	CREATE INDEX IF NOT EXISTS idx_sandboxes_updated_at ON sandboxes(updated_at);
	CREATE INDEX IF NOT EXISTS idx_sandboxes_deleted_at ON sandboxes(deleted_at);

	CREATE INDEX IF NOT EXISTS idx_file_metadata_sandbox_id ON file_metadata(sandbox_id);
	CREATE INDEX IF NOT EXISTS idx_file_metadata_path ON file_metadata(file_path);
	CREATE INDEX IF NOT EXISTS idx_file_metadata_checksum ON file_metadata(checksum);
	CREATE INDEX IF NOT EXISTS idx_file_metadata_created_at ON file_metadata(created_at);
	CREATE INDEX IF NOT EXISTS idx_file_metadata_deleted_at ON file_metadata(deleted_at);

	CREATE INDEX IF NOT EXISTS idx_metrics_name_timestamp ON metrics(metric_name, timestamp);
	CREATE INDEX IF NOT EXISTS idx_metrics_sandbox_timestamp ON metrics(sandbox_id, timestamp);
	CREATE INDEX IF NOT EXISTS idx_metrics_type_period ON metrics(metric_type, aggregation_period);

	CREATE INDEX IF NOT EXISTS idx_audit_trail_entity ON audit_trail(entity_type, entity_id);
	CREATE INDEX IF NOT EXISTS idx_audit_trail_timestamp ON audit_trail(timestamp);


	-- Trigger for updating updated_at timestamps
	CREATE TRIGGER IF NOT EXISTS update_sandboxes_updated_at 
		AFTER UPDATE ON sandboxes 
		FOR EACH ROW 
		WHEN NEW.updated_at = OLD.updated_at
	BEGIN
		UPDATE sandboxes SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
	END;

	CREATE TRIGGER IF NOT EXISTS update_file_metadata_updated_at 
		AFTER UPDATE ON file_metadata 
		FOR EACH ROW 
		WHEN NEW.updated_at = OLD.updated_at
	BEGIN
		UPDATE file_metadata SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
	END;
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	// Try to create FTS5 virtual table if available
	ftsSchema := `
		-- Full-text search virtual table for file content
		CREATE VIRTUAL TABLE IF NOT EXISTS file_search_fts USING fts5(
			file_path,
			search_content,
			content='file_metadata',
			content_rowid='id'
		);

		-- Triggers for maintaining FTS index
		CREATE TRIGGER IF NOT EXISTS file_metadata_ai AFTER INSERT ON file_metadata BEGIN
			INSERT INTO file_search_fts(rowid, file_path, search_content) 
			VALUES (new.id, new.file_path, new.search_content);
		END;

		CREATE TRIGGER IF NOT EXISTS file_metadata_ad AFTER DELETE ON file_metadata BEGIN
			INSERT INTO file_search_fts(file_search_fts, rowid, file_path, search_content) 
			VALUES('delete', old.id, old.file_path, old.search_content);
		END;

		CREATE TRIGGER IF NOT EXISTS file_metadata_au AFTER UPDATE ON file_metadata BEGIN
			INSERT INTO file_search_fts(file_search_fts, rowid, file_path, search_content) 
			VALUES('delete', old.id, old.file_path, old.search_content);
			INSERT INTO file_search_fts(rowid, file_path, search_content) 
			VALUES (new.id, new.file_path, new.search_content);
		END;
	`

	// Try to create FTS5 tables, but don't fail if FTS5 is not available
	if _, err := s.db.Exec(ftsSchema); err != nil {
		log.Warn().Err(err).Msg("FTS5 not available, search functionality will be limited")
	}

	// Mark initial migration as applied
	s.migrationVer = 1
	_, err := s.db.Exec("INSERT OR IGNORE INTO migrations (version, description) VALUES (?, ?)",
		s.migrationVer, "Initial schema")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to record initial migration")
	}

	return nil
}

// BeginTransaction starts a new database transaction
func (s *SQLiteStore) BeginTransaction(ctx context.Context) (*Transaction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, fmt.Errorf("store is closed")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.metrics.mu.Lock()
		s.metrics.ErrorCount++
		s.metrics.mu.Unlock()
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	s.metrics.mu.Lock()
	s.metrics.TransactionCount++
	s.metrics.mu.Unlock()

	return &Transaction{
		tx:     tx,
		store:  s,
		active: true,
	}, nil
}

// Commit commits the transaction
func (t *Transaction) Commit() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.active {
		return fmt.Errorf("transaction is not active")
	}

	err := t.tx.Commit()
	t.active = false

	if err != nil {
		t.store.metrics.mu.Lock()
		t.store.metrics.ErrorCount++
		t.store.metrics.mu.Unlock()
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Rollback rolls back the transaction
func (t *Transaction) Rollback() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.active {
		return nil // Already rolled back or committed
	}

	err := t.tx.Rollback()
	t.active = false

	if err != nil {
		t.store.metrics.mu.Lock()
		t.store.metrics.ErrorCount++
		t.store.metrics.mu.Unlock()
		return fmt.Errorf("failed to rollback transaction: %w", err)
	}

	return nil
}

// Exec executes a query within the transaction
func (t *Transaction) Exec(query string, args ...interface{}) (sql.Result, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.active {
		return nil, fmt.Errorf("transaction is not active")
	}

	t.store.metrics.mu.Lock()
	t.store.metrics.QueryCount++
	t.store.metrics.mu.Unlock()

	result, err := t.tx.Exec(query, args...)
	if err != nil {
		t.store.metrics.mu.Lock()
		t.store.metrics.ErrorCount++
		t.store.metrics.mu.Unlock()
	}

	return result, err
}

// Query executes a query within the transaction
func (t *Transaction) Query(query string, args ...interface{}) (*sql.Rows, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.active {
		return nil, fmt.Errorf("transaction is not active")
	}

	t.store.metrics.mu.Lock()
	t.store.metrics.QueryCount++
	t.store.metrics.mu.Unlock()

	rows, err := t.tx.Query(query, args...)
	if err != nil {
		t.store.metrics.mu.Lock()
		t.store.metrics.ErrorCount++
		t.store.metrics.mu.Unlock()
	}

	return rows, err
}

// QueryRow executes a single-row query within the transaction
func (t *Transaction) QueryRow(query string, args ...interface{}) *sql.Row {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.store.metrics.mu.Lock()
	t.store.metrics.QueryCount++
	t.store.metrics.mu.Unlock()

	return t.tx.QueryRow(query, args...)
}

// Exec executes a query outside of a transaction
func (s *SQLiteStore) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, fmt.Errorf("store is closed")
	}

	s.metrics.mu.Lock()
	s.metrics.QueryCount++
	s.metrics.mu.Unlock()

	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		s.metrics.mu.Lock()
		s.metrics.ErrorCount++
		s.metrics.mu.Unlock()
	}

	return result, err
}

// Query executes a query outside of a transaction
func (s *SQLiteStore) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, fmt.Errorf("store is closed")
	}

	s.metrics.mu.Lock()
	s.metrics.QueryCount++
	s.metrics.mu.Unlock()

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		s.metrics.mu.Lock()
		s.metrics.ErrorCount++
		s.metrics.mu.Unlock()
	}

	return rows, err
}

// QueryRow executes a single-row query outside of a transaction
func (s *SQLiteStore) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.metrics.mu.Lock()
	s.metrics.QueryCount++
	s.metrics.mu.Unlock()

	return s.db.QueryRowContext(ctx, query, args...)
}

// GetMetrics returns current storage metrics
func (s *SQLiteStore) GetMetrics() StorageMetrics {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	// Update database size
	if stat, err := os.Stat(s.dbPath); err == nil {
		s.metrics.DatabaseSize = stat.Size()
	}

	return *s.metrics
}

// Close closes the database connection
func (s *SQLiteStore) Close() error {
	s.mu.Lock()
	
	if s.closed {
		s.mu.Unlock()
		return nil
	}

	db := s.db
	backupDir := s.backupDir
	
	// Perform final backup before closing
	if backupDir != "" {
		timestamp := time.Now().Format("20060102_150405")
		backupPath := filepath.Join(backupDir, fmt.Sprintf("sandbox_runner_%s.db", timestamp))
		query := fmt.Sprintf("VACUUM INTO '%s'", backupPath)
		
		if _, err := db.Exec(query); err != nil {
			log.Warn().Err(err).Msg("Failed to perform final backup")
		} else {
			log.Info().Str("backup_path", backupPath).Msg("Final backup created successfully")
		}
	}

	s.closed = true
	s.mu.Unlock()

	if err := db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}

	log.Info().Msg("SQLite store closed successfully")
	return nil
}

// startBackupScheduler runs periodic backups
func (s *SQLiteStore) startBackupScheduler(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.backup(); err != nil {
				log.Error().Err(err).Msg("Scheduled backup failed")
			}
		}
	}
}

// backup creates a backup of the database
func (s *SQLiteStore) backup() error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return fmt.Errorf("store is closed")
	}
	
	db := s.db
	backupDir := s.backupDir
	s.mu.RUnlock()

	timestamp := time.Now().Format("20060102_150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("sandbox_runner_%s.db", timestamp))

	// Use SQLite's backup API for consistent backups
	query := fmt.Sprintf("VACUUM INTO '%s'", backupPath)
	
	_, err := db.Exec(query)
	if err != nil {
		s.metrics.mu.Lock()
		s.metrics.ErrorCount++
		s.metrics.mu.Unlock()
		return fmt.Errorf("failed to create backup: %w", err)
	}

	s.metrics.mu.Lock()
	s.metrics.BackupCount++
	s.metrics.LastBackup = time.Now()
	s.metrics.mu.Unlock()

	log.Info().
		Str("backup_path", backupPath).
		Msg("Database backup created successfully")

	// Clean up old backups (keep last 7)
	go s.cleanupOldBackups(7)

	return nil
}

// cleanupOldBackups removes old backup files
func (s *SQLiteStore) cleanupOldBackups(keepCount int) {
	files, err := filepath.Glob(filepath.Join(s.backupDir, "sandbox_runner_*.db"))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list backup files")
		return
	}

	if len(files) <= keepCount {
		return
	}

	// Sort by modification time and remove oldest
	type fileInfo struct {
		path    string
		modTime time.Time
	}

	var fileInfos []fileInfo
	for _, file := range files {
		stat, err := os.Stat(file)
		if err != nil {
			continue
		}
		fileInfos = append(fileInfos, fileInfo{
			path:    file,
			modTime: stat.ModTime(),
		})
	}

	// Sort by modification time, newest first
	for i := 0; i < len(fileInfos)-1; i++ {
		for j := i + 1; j < len(fileInfos); j++ {
			if fileInfos[i].modTime.Before(fileInfos[j].modTime) {
				fileInfos[i], fileInfos[j] = fileInfos[j], fileInfos[i]
			}
		}
	}

	// Remove oldest files
	for i := keepCount; i < len(fileInfos); i++ {
		if err := os.Remove(fileInfos[i].path); err != nil {
			log.Warn().Err(err).Str("file", fileInfos[i].path).Msg("Failed to remove old backup")
		} else {
			log.Debug().Str("file", fileInfos[i].path).Msg("Removed old backup file")
		}
	}
}

// RestoreFromBackup restores the database from a backup file
func (s *SQLiteStore) RestoreFromBackup(backupPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("store is closed")
	}

	// Verify backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %s", backupPath)
	}

	// Close current connection
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("failed to close current database: %w", err)
	}

	// Replace database file
	if err := os.Remove(s.dbPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove current database: %w", err)
	}

	if err := copyFile(backupPath, s.dbPath); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	// Reopen database
	dsn := fmt.Sprintf("%s?_foreign_keys=on&_journal_mode=WAL&_synchronous=NORMAL&_cache_size=-64000&_temp_store=MEMORY", s.dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return fmt.Errorf("failed to reopen database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(s.connPool.maxOpenConns)
	db.SetMaxIdleConns(s.connPool.maxIdleConns)
	db.SetConnMaxLifetime(s.connPool.connMaxLifetime)
	db.SetConnMaxIdleTime(s.connPool.connMaxIdleTime)

	s.db = db

	log.Info().
		Str("backup_path", backupPath).
		Str("database_path", s.dbPath).
		Msg("Database restored from backup successfully")

	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = sourceFile.WriteTo(destFile)
	return err
}

// Vacuum optimizes the database
func (s *SQLiteStore) Vacuum(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return fmt.Errorf("store is closed")
	}

	log.Info().Msg("Starting database vacuum")
	
	_, err := s.db.ExecContext(ctx, "VACUUM")
	if err != nil {
		s.metrics.mu.Lock()
		s.metrics.ErrorCount++
		s.metrics.mu.Unlock()
		return fmt.Errorf("failed to vacuum database: %w", err)
	}

	log.Info().Msg("Database vacuum completed successfully")
	return nil
}

// CheckIntegrity performs database integrity check
func (s *SQLiteStore) CheckIntegrity(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return fmt.Errorf("store is closed")
	}

	row := s.db.QueryRowContext(ctx, "PRAGMA integrity_check")
	var result string
	if err := row.Scan(&result); err != nil {
		return fmt.Errorf("failed to check integrity: %w", err)
	}

	if result != "ok" {
		return fmt.Errorf("database integrity check failed: %s", result)
	}

	log.Info().Msg("Database integrity check passed")
	return nil
}