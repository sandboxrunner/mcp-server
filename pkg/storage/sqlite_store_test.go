package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSQLiteStore(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DatabasePath:    filepath.Join(tempDir, "test.db"),
		BackupDir:       filepath.Join(tempDir, "backups"),
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 10,
		EnableBackup:    false, // Disable for testing
	}

	store, err := NewSQLiteStore(config)
	require.NoError(t, err)
	require.NotNil(t, store)

	defer store.Close()

	// Test database connection
	ctx := context.Background()
	row := store.QueryRow(ctx, "SELECT 1")
	var result int
	err = row.Scan(&result)
	assert.NoError(t, err)
	assert.Equal(t, 1, result)
}

func TestSQLiteStore_Transactions(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	ctx := context.Background()

	t.Run("successful transaction", func(t *testing.T) {
		tx, err := store.BeginTransaction(ctx)
		require.NoError(t, err)

		// Insert test data
		_, err = tx.Exec("INSERT INTO sandboxes (id, status, created_at, updated_at, config, metadata, environment) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"test-tx-1", "running", time.Now(), time.Now(), "{}", "{}", "{}")
		require.NoError(t, err)

		// Commit transaction
		err = tx.Commit()
		require.NoError(t, err)

		// Verify data exists
		row := store.QueryRow(ctx, "SELECT id FROM sandboxes WHERE id = ?", "test-tx-1")
		var id string
		err = row.Scan(&id)
		assert.NoError(t, err)
		assert.Equal(t, "test-tx-1", id)
	})

	t.Run("rollback transaction", func(t *testing.T) {
		tx, err := store.BeginTransaction(ctx)
		require.NoError(t, err)

		// Insert test data
		_, err = tx.Exec("INSERT INTO sandboxes (id, status, created_at, updated_at, config, metadata, environment) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"test-tx-2", "running", time.Now(), time.Now(), "{}", "{}", "{}")
		require.NoError(t, err)

		// Rollback transaction
		err = tx.Rollback()
		require.NoError(t, err)

		// Verify data doesn't exist
		row := store.QueryRow(ctx, "SELECT id FROM sandboxes WHERE id = ?", "test-tx-2")
		var id string
		err = row.Scan(&id)
		assert.Error(t, err) // Should be no rows
	})
}

func TestSQLiteStore_Backup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sqlite_backup_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DatabasePath:    filepath.Join(tempDir, "test.db"),
		BackupDir:       filepath.Join(tempDir, "backups"),
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 10,
		EnableBackup:    false, // We'll test manually
	}

	store, err := NewSQLiteStore(config)
	require.NoError(t, err)
	defer store.Close()

	ctx := context.Background()

	// Insert test data
	_, err = store.Exec(ctx, "INSERT INTO sandboxes (id, status, created_at, updated_at, config, metadata, environment) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"test-backup", "running", time.Now(), time.Now(), "{}", "{}", "{}")
	require.NoError(t, err)

	// Create backup
	err = store.backup()
	require.NoError(t, err)

	// Check backup file exists
	backupFiles, err := filepath.Glob(filepath.Join(tempDir, "backups", "sandbox_runner_*.db"))
	require.NoError(t, err)
	assert.Len(t, backupFiles, 1)

	// Test restore
	backupPath := backupFiles[0]
	err = store.RestoreFromBackup(backupPath)
	require.NoError(t, err)

	// Verify data still exists after restore
	row := store.QueryRow(ctx, "SELECT id FROM sandboxes WHERE id = ?", "test-backup")
	var id string
	err = row.Scan(&id)
	assert.NoError(t, err)
	assert.Equal(t, "test-backup", id)
}

func TestSQLiteStore_Vacuum(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	ctx := context.Background()

	err := store.Vacuum(ctx)
	assert.NoError(t, err)
}

func TestSQLiteStore_CheckIntegrity(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	ctx := context.Background()

	err := store.CheckIntegrity(ctx)
	assert.NoError(t, err)
}

func TestSQLiteStore_Metrics(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	ctx := context.Background()

	// Perform some operations to generate metrics
	_, err := store.Exec(ctx, "SELECT 1")
	require.NoError(t, err)

	tx, err := store.BeginTransaction(ctx)
	require.NoError(t, err)
	err = tx.Commit()
	require.NoError(t, err)

	// Get metrics
	metrics := store.GetMetrics()
	assert.Greater(t, metrics.QueryCount, int64(0))
	assert.Greater(t, metrics.TransactionCount, int64(0))
}

func TestSQLiteStore_ConcurrentAccess(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	ctx := context.Background()
	concurrency := 10
	done := make(chan bool, concurrency)

	// Run concurrent operations
	for i := 0; i < concurrency; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Insert data
			_, err := store.Exec(ctx, "INSERT INTO sandboxes (id, status, created_at, updated_at, config, metadata, environment) VALUES (?, ?, ?, ?, ?, ?, ?)",
				fmt.Sprintf("concurrent-test-%d", id), "running", time.Now(), time.Now(), "{}", "{}", "{}")
			assert.NoError(t, err)

			// Read data
			row := store.QueryRow(ctx, "SELECT COUNT(*) FROM sandboxes")
			var count int
			err = row.Scan(&count)
			assert.NoError(t, err)

			// Use transaction
			tx, err := store.BeginTransaction(ctx)
			if assert.NoError(t, err) {
				_, err = tx.Exec("UPDATE sandboxes SET status = 'updated' WHERE id = ?", fmt.Sprintf("concurrent-test-%d", id))
				assert.NoError(t, err)
				err = tx.Commit()
				assert.NoError(t, err)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < concurrency; i++ {
		<-done
	}

	// Verify all data was inserted
	row := store.QueryRow(ctx, "SELECT COUNT(*) FROM sandboxes WHERE id LIKE 'concurrent-test-%'")
	var count int
	err := row.Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, concurrency, count)
}

func TestSQLiteStore_ErrorHandling(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	ctx := context.Background()

	t.Run("invalid SQL", func(t *testing.T) {
		_, err := store.Exec(ctx, "INVALID SQL STATEMENT")
		assert.Error(t, err)

		// Check error count increased
		metrics := store.GetMetrics()
		assert.Greater(t, metrics.ErrorCount, int64(0))
	})

	t.Run("constraint violation", func(t *testing.T) {
		// Insert duplicate primary key
		_, err := store.Exec(ctx, "INSERT INTO sandboxes (id, status, created_at, updated_at, config, metadata, environment) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"duplicate-test", "running", time.Now(), time.Now(), "{}", "{}", "{}")
		require.NoError(t, err)

		_, err = store.Exec(ctx, "INSERT INTO sandboxes (id, status, created_at, updated_at, config, metadata, environment) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"duplicate-test", "running", time.Now(), time.Now(), "{}", "{}", "{}")
		assert.Error(t, err)
	})

	t.Run("transaction rollback on error", func(t *testing.T) {
		tx, err := store.BeginTransaction(ctx)
		require.NoError(t, err)

		// Valid operation
		_, err = tx.Exec("INSERT INTO sandboxes (id, status, created_at, updated_at, config, metadata, environment) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"tx-error-test", "running", time.Now(), time.Now(), "{}", "{}", "{}")
		require.NoError(t, err)

		// Invalid operation
		_, err = tx.Exec("INVALID SQL")
		assert.Error(t, err)

		// Rollback due to error
		err = tx.Rollback()
		assert.NoError(t, err)

		// Verify data was not inserted
		row := store.QueryRow(ctx, "SELECT id FROM sandboxes WHERE id = ?", "tx-error-test")
		var id string
		err = row.Scan(&id)
		assert.Error(t, err) // Should be no rows
	})
}

func TestSQLiteStore_ClosedStore(t *testing.T) {
	store := setupTestStore(t)
	store.Close()

	ctx := context.Background()

	// Operations on closed store should fail
	_, err := store.Exec(ctx, "SELECT 1")
	assert.Error(t, err)

	_, err = store.BeginTransaction(ctx)
	assert.Error(t, err)

	err = store.Vacuum(ctx)
	assert.Error(t, err)
}

// setupTestStore creates a test SQLite store
func setupTestStore(t *testing.T) *SQLiteStore {
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	config := &Config{
		DatabasePath:    filepath.Join(tempDir, "test.db"),
		BackupDir:       filepath.Join(tempDir, "backups"),
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 10,
		EnableBackup:    false, // Disable for testing
	}

	store, err := NewSQLiteStore(config)
	require.NoError(t, err)
	require.NotNil(t, store)

	return store
}

func BenchmarkSQLiteStore_Insert(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "sqlite_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DatabasePath:    filepath.Join(tempDir, "bench.db"),
		BackupDir:       filepath.Join(tempDir, "backups"),
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 10,
		EnableBackup:    false,
	}

	store, err := NewSQLiteStore(config)
	require.NoError(b, err)
	defer store.Close()

	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := store.Exec(ctx, "INSERT INTO sandboxes (id, status, created_at, updated_at, config, metadata, environment) VALUES (?, ?, ?, ?, ?, ?, ?)",
			fmt.Sprintf("bench-test-%d", i), "running", time.Now(), time.Now(), "{}", "{}", "{}")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSQLiteStore_Select(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "sqlite_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DatabasePath:    filepath.Join(tempDir, "bench.db"),
		BackupDir:       filepath.Join(tempDir, "backups"),
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 10,
		EnableBackup:    false,
	}

	store, err := NewSQLiteStore(config)
	require.NoError(b, err)
	defer store.Close()

	ctx := context.Background()

	// Insert test data
	for i := 0; i < 1000; i++ {
		_, err := store.Exec(ctx, "INSERT INTO sandboxes (id, status, created_at, updated_at, config, metadata, environment) VALUES (?, ?, ?, ?, ?, ?, ?)",
			fmt.Sprintf("bench-select-%d", i), "running", time.Now(), time.Now(), "{}", "{}", "{}")
		require.NoError(b, err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		row := store.QueryRow(ctx, "SELECT id, status FROM sandboxes WHERE id = ?", fmt.Sprintf("bench-select-%d", i%1000))
		var id, status string
		err := row.Scan(&id, &status)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSQLiteStore_Transaction(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "sqlite_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DatabasePath:    filepath.Join(tempDir, "bench.db"),
		BackupDir:       filepath.Join(tempDir, "backups"),
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 10,
		EnableBackup:    false,
	}

	store, err := NewSQLiteStore(config)
	require.NoError(b, err)
	defer store.Close()

	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tx, err := store.BeginTransaction(ctx)
		if err != nil {
			b.Fatal(err)
		}

		_, err = tx.Exec("INSERT INTO sandboxes (id, status, created_at, updated_at, config, metadata, environment) VALUES (?, ?, ?, ?, ?, ?, ?)",
			fmt.Sprintf("bench-tx-%d", i), "running", time.Now(), time.Now(), "{}", "{}", "{}")
		if err != nil {
			b.Fatal(err)
		}

		err = tx.Commit()
		if err != nil {
			b.Fatal(err)
		}
	}
}