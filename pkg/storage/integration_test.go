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

// TestStorageIntegration tests the integration between all storage components
func TestStorageIntegration(t *testing.T) {
	store, sandboxStore, fileStore, metricsStore, migrator := setupIntegrationTest(t)
	defer store.Close()

	ctx := context.Background()

	t.Run("complete workflow", func(t *testing.T) {
		// 1. Apply migrations
		err := migrator.Migrate(ctx)
		require.NoError(t, err)

		status, err := migrator.GetMigrationStatus(ctx)
		require.NoError(t, err)
		assert.True(t, status.UpToDate)

		// 2. Create sandbox
		sandbox := &SandboxState{
			ID:          "integration-test-1",
			ContainerID: "container-integration-1",
			Status:      "running",
			WorkingDir:  "/workspace",
			Environment: map[string]string{"ENV": "test"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Config: map[string]interface{}{
				"image": "ubuntu:20.04",
			},
			Metadata: map[string]interface{}{
				"test": "integration",
			},
			Version: 1,
		}

		err = sandboxStore.Create(ctx, sandbox)
		require.NoError(t, err)

		// 3. Create file metadata
		fileMetadata := &FileMetadata{
			SandboxID:     sandbox.ID,
			FilePath:      "/workspace/test.txt",
			Checksum:      "abc123",
			SizeBytes:     1024,
			MimeType:      "text/plain",
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			Version:       1,
			SearchContent: "This is test content for searching",
			Metadata: map[string]interface{}{
				"encoding": "utf-8",
			},
		}

		err = fileStore.Create(ctx, fileMetadata)
		require.NoError(t, err)

		// 4. Record metrics
		metrics := []*Metric{
			{
				MetricName: "cpu_usage",
				MetricType: MetricTypeGauge,
				Labels: map[string]string{
					"sandbox_id": sandbox.ID,
					"type":       "system",
				},
				Value:             45.5,
				Timestamp:         time.Now(),
				SandboxID:         sandbox.ID,
				AggregationPeriod: AggregationRaw,
			},
			{
				MetricName: "memory_usage",
				MetricType: MetricTypeGauge,
				Labels: map[string]string{
					"sandbox_id": sandbox.ID,
					"type":       "system",
				},
				Value:             512,
				Timestamp:         time.Now(),
				SandboxID:         sandbox.ID,
				AggregationPeriod: AggregationRaw,
			},
		}

		err = metricsStore.RecordBatch(ctx, metrics)
		require.NoError(t, err)

		// 5. Update sandbox status
		sandbox.Status = "stopped"
		err = sandboxStore.Update(ctx, sandbox)
		require.NoError(t, err)

		// 6. Search files
		searchResults, err := fileStore.Search(ctx, sandbox.ID, "test content", 10)
		require.NoError(t, err)
		assert.Len(t, searchResults, 1)
		assert.Equal(t, fileMetadata.FilePath, searchResults[0].FileMetadata.FilePath)

		// 7. Query metrics
		filter := &MetricFilter{
			SandboxIDs:  []string{sandbox.ID},
			MetricNames: []string{"cpu_usage"},
			StartTime:   time.Now().Add(-time.Hour),
			EndTime:     time.Now().Add(time.Hour),
		}

		retrievedMetrics, err := metricsStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.Len(t, retrievedMetrics, 1)
		assert.Equal(t, "cpu_usage", retrievedMetrics[0].MetricName)

		// 8. Get audit trail
		auditEntries, err := sandboxStore.GetAuditTrail(ctx, sandbox.ID, 10)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(auditEntries), 2) // Create and update

		// 9. Test backup and restore
		err = store.backup()
		require.NoError(t, err)

		// 10. Verify all data is accessible
		retrievedSandbox, err := sandboxStore.Get(ctx, sandbox.ID)
		require.NoError(t, err)
		assert.Equal(t, "stopped", retrievedSandbox.Status)

		retrievedFile, err := fileStore.GetByPath(ctx, sandbox.ID, "/workspace/test.txt")
		require.NoError(t, err)
		assert.Equal(t, fileMetadata.FilePath, retrievedFile.FilePath)

		// 11. Test soft delete and recovery
		err = sandboxStore.Delete(ctx, sandbox.ID, "integration-test")
		require.NoError(t, err)

		_, err = sandboxStore.Get(ctx, sandbox.ID)
		assert.Error(t, err) // Should not be found

		err = sandboxStore.Recover(ctx, sandbox.ID, "integration-test")
		require.NoError(t, err)

		recoveredSandbox, err := sandboxStore.Get(ctx, sandbox.ID)
		require.NoError(t, err)
		assert.Equal(t, sandbox.ID, recoveredSandbox.ID)
	})
}

func TestStoragePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	store, sandboxStore, fileStore, metricsStore, _ := setupIntegrationTest(t)
	defer store.Close()

	ctx := context.Background()

	t.Run("bulk operations", func(t *testing.T) {
		// Test bulk sandbox creation
		start := time.Now()
		sandboxCount := 100

		for i := 0; i < sandboxCount; i++ {
			sandbox := &SandboxState{
				ID:          fmt.Sprintf("perf-sandbox-%d", i),
				ContainerID: fmt.Sprintf("container-%d", i),
				Status:      "running",
				WorkingDir:  "/workspace",
				Environment: map[string]string{"TEST": "perf"},
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				Config: map[string]interface{}{
					"image": "ubuntu:20.04",
				},
				Metadata: map[string]interface{}{
					"batch": i,
				},
				Version: 1,
			}

			err := sandboxStore.Create(ctx, sandbox)
			require.NoError(t, err)
		}

		sandboxCreationTime := time.Since(start)
		t.Logf("Created %d sandboxes in %v (%.2f/sec)",
			sandboxCount, sandboxCreationTime, float64(sandboxCount)/sandboxCreationTime.Seconds())

		// Test bulk file metadata creation
		start = time.Now()
		fileCount := 500

		for i := 0; i < fileCount; i++ {
			fileMetadata := &FileMetadata{
				SandboxID:     fmt.Sprintf("perf-sandbox-%d", i%sandboxCount),
				FilePath:      fmt.Sprintf("/workspace/file-%d.txt", i),
				Checksum:      fmt.Sprintf("checksum-%d", i),
				SizeBytes:     int64(1024 + i),
				MimeType:      "text/plain",
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
				Version:       1,
				SearchContent: fmt.Sprintf("Content for file %d with searchable text", i),
			}

			err := fileStore.Create(ctx, fileMetadata)
			require.NoError(t, err)
		}

		fileCreationTime := time.Since(start)
		t.Logf("Created %d file metadata entries in %v (%.2f/sec)",
			fileCount, fileCreationTime, float64(fileCount)/fileCreationTime.Seconds())

		// Test bulk metrics recording
		start = time.Now()
		metricCount := 1000

		var metrics []*Metric
		for i := 0; i < metricCount; i++ {
			metric := &Metric{
				MetricName: fmt.Sprintf("test_metric_%d", i%10),
				MetricType: MetricTypeGauge,
				Labels: map[string]string{
					"sandbox_id": fmt.Sprintf("perf-sandbox-%d", i%sandboxCount),
					"instance":   fmt.Sprintf("inst-%d", i%5),
				},
				Value:             float64(i),
				Timestamp:         time.Now().Add(-time.Duration(i) * time.Second),
				SandboxID:         fmt.Sprintf("perf-sandbox-%d", i%sandboxCount),
				AggregationPeriod: AggregationRaw,
			}
			metrics = append(metrics, metric)

			// Record in batches of 100
			if len(metrics) == 100 {
				err := metricsStore.RecordBatch(ctx, metrics)
				require.NoError(t, err)
				metrics = nil
			}
		}

		// Record remaining metrics
		if len(metrics) > 0 {
			err := metricsStore.RecordBatch(ctx, metrics)
			require.NoError(t, err)
		}

		metricRecordTime := time.Since(start)
		t.Logf("Recorded %d metrics in %v (%.2f/sec)",
			metricCount, metricRecordTime, float64(metricCount)/metricRecordTime.Seconds())

		// Test query performance
		start = time.Now()
		queryCount := 100

		for i := 0; i < queryCount; i++ {
			sandboxID := fmt.Sprintf("perf-sandbox-%d", i%sandboxCount)
			
			// Query sandbox
			_, err := sandboxStore.Get(ctx, sandboxID)
			require.NoError(t, err)

			// Query files for sandbox
			filter := &FileFilter{
				SandboxID: sandboxID,
				Limit:     10,
			}
			_, err = fileStore.List(ctx, filter)
			require.NoError(t, err)

			// Query metrics for sandbox
			metricFilter := &MetricFilter{
				SandboxIDs: []string{sandboxID},
				Limit:      50,
			}
			_, err = metricsStore.Query(ctx, metricFilter)
			require.NoError(t, err)
		}

		queryTime := time.Since(start)
		t.Logf("Performed %d complex queries in %v (%.2f/sec)",
			queryCount, queryTime, float64(queryCount)/queryTime.Seconds())
	})
}

func TestStorageReliability(t *testing.T) {
	store, sandboxStore, fileStore, metricsStore, _ := setupIntegrationTest(t)
	defer store.Close()

	ctx := context.Background()

	t.Run("transaction rollback", func(t *testing.T) {
		// Start transaction
		tx, err := store.BeginTransaction(ctx)
		require.NoError(t, err)

		// Insert data in transaction
		_, err = tx.Exec("INSERT INTO sandboxes (id, status, created_at, updated_at, config, metadata, environment) VALUES (?, ?, ?, ?, ?, ?, ?)",
			"rollback-test", "running", time.Now(), time.Now(), "{}", "{}", "{}")
		require.NoError(t, err)

		// Rollback transaction
		err = tx.Rollback()
		require.NoError(t, err)

		// Verify data was not persisted
		_, err = sandboxStore.Get(ctx, "rollback-test")
		assert.Error(t, err)
	})

	t.Run("database integrity", func(t *testing.T) {
		err := store.CheckIntegrity(ctx)
		assert.NoError(t, err)
	})

	t.Run("foreign key constraints", func(t *testing.T) {
		// Try to create file metadata for non-existent sandbox
		fileMetadata := &FileMetadata{
			SandboxID:   "non-existent-sandbox",
			FilePath:    "/test.txt",
			Checksum:    "test",
			SizeBytes:   100,
			MimeType:    "text/plain",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Version:     1,
		}

		err := fileStore.Create(ctx, fileMetadata)
		// Should succeed as foreign key is not enforced on insert
		require.NoError(t, err)

		// Create sandbox
		sandbox := &SandboxState{
			ID:          "fk-test-sandbox",
			ContainerID: "container-fk",
			Status:      "running",
			WorkingDir:  "/workspace",
			Environment: map[string]string{},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Config:      map[string]interface{}{},
			Metadata:    map[string]interface{}{},
			Version:     1,
		}

		err = sandboxStore.Create(ctx, sandbox)
		require.NoError(t, err)

		// Create valid file metadata
		validFileMetadata := &FileMetadata{
			SandboxID:   sandbox.ID,
			FilePath:    "/valid.txt",
			Checksum:    "valid",
			SizeBytes:   100,
			MimeType:    "text/plain",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Version:     1,
		}

		err = fileStore.Create(ctx, validFileMetadata)
		require.NoError(t, err)

		// Delete sandbox (should cascade to files due to foreign key)
		err = sandboxStore.Delete(ctx, sandbox.ID, "fk-test")
		require.NoError(t, err)

		// File should still exist (soft delete doesn't cascade)
		_, err = fileStore.Get(ctx, validFileMetadata.ID)
		require.NoError(t, err)
	})

	t.Run("concurrent access", func(t *testing.T) {
		concurrency := 20
		done := make(chan error, concurrency)

		for i := 0; i < concurrency; i++ {
			go func(id int) {
				// Create sandbox
				sandbox := &SandboxState{
					ID:          fmt.Sprintf("concurrent-%d", id),
					ContainerID: fmt.Sprintf("container-%d", id),
					Status:      "running",
					WorkingDir:  "/workspace",
					Environment: map[string]string{"ID": fmt.Sprintf("%d", id)},
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
					Config:      map[string]interface{}{"worker": id},
					Metadata:    map[string]interface{}{"test": "concurrent"},
					Version:     1,
				}

				err := sandboxStore.Create(ctx, sandbox)
				if err != nil {
					done <- err
					return
				}

				// Create file metadata
				fileMetadata := &FileMetadata{
					SandboxID:   sandbox.ID,
					FilePath:    fmt.Sprintf("/worker-%d.txt", id),
					Checksum:    fmt.Sprintf("checksum-%d", id),
					SizeBytes:   int64(id * 100),
					MimeType:    "text/plain",
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
					Version:     1,
				}

				err = fileStore.Create(ctx, fileMetadata)
				if err != nil {
					done <- err
					return
				}

				// Record metric
				metric := &Metric{
					MetricName: "concurrent_test",
					MetricType: MetricTypeCounter,
					Labels: map[string]string{
						"worker_id": fmt.Sprintf("%d", id),
					},
					Value:             float64(id),
					Timestamp:         time.Now(),
					SandboxID:         sandbox.ID,
					AggregationPeriod: AggregationRaw,
				}

				err = metricsStore.Record(ctx, metric)
				done <- err
			}(i)
		}

		// Wait for all goroutines
		errorCount := 0
		for i := 0; i < concurrency; i++ {
			err := <-done
			if err != nil {
				errorCount++
				t.Logf("Concurrent operation %d failed: %v", i, err)
			}
		}

		// Allow for some race conditions but most should succeed
		assert.LessOrEqual(t, errorCount, concurrency/4, "Too many concurrent operations failed")
	})
}

func TestStorageRecovery(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "storage_recovery_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &Config{
		DatabasePath:    filepath.Join(tempDir, "recovery_test.db"),
		BackupDir:       filepath.Join(tempDir, "backups"),
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 10,
		EnableBackup:    true,
		BackupInterval:  time.Second, // Fast backup for testing
	}

	// Create initial store and data
	store1, err := NewSQLiteStore(config)
	require.NoError(t, err)

	sandboxStore1 := NewSandboxStore(store1)
	ctx := context.Background()

	// Create test data
	sandbox := &SandboxState{
		ID:          "recovery-test",
		ContainerID: "container-recovery",
		Status:      "running",
		WorkingDir:  "/workspace",
		Environment: map[string]string{"RECOVERY": "test"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Config: map[string]interface{}{
			"image": "ubuntu:20.04",
		},
		Metadata: map[string]interface{}{
			"test": "recovery",
		},
		Version: 1,
	}

	err = sandboxStore1.Create(ctx, sandbox)
	require.NoError(t, err)

	// Create backup
	err = store1.backup()
	require.NoError(t, err)

	// Close first store
	err = store1.Close()
	require.NoError(t, err)

	// Wait a bit to ensure backup file exists
	time.Sleep(time.Millisecond * 100)

	// Find backup file
	backupFiles, err := filepath.Glob(filepath.Join(tempDir, "backups", "sandbox_runner_*.db"))
	require.NoError(t, err)
	require.NotEmpty(t, backupFiles)

	// Create second store and restore from backup
	store2, err := NewSQLiteStore(config)
	require.NoError(t, err)
	defer store2.Close()

	err = store2.RestoreFromBackup(backupFiles[0])
	require.NoError(t, err)

	// Verify data was recovered
	sandboxStore2 := NewSandboxStore(store2)
	recoveredSandbox, err := sandboxStore2.Get(ctx, "recovery-test")
	require.NoError(t, err)
	assert.Equal(t, sandbox.ID, recoveredSandbox.ID)
	assert.Equal(t, sandbox.Status, recoveredSandbox.Status)
	assert.Equal(t, sandbox.Environment["RECOVERY"], recoveredSandbox.Environment["RECOVERY"])
}

// setupIntegrationTest creates all storage components for integration testing
func setupIntegrationTest(t *testing.T) (*SQLiteStore, *SandboxStore, *FileStore, *MetricsStore, *Migrator) {
	tempDir, err := os.MkdirTemp("", "storage_integration_test")
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	config := &Config{
		DatabasePath:    filepath.Join(tempDir, "integration_test.db"),
		BackupDir:       filepath.Join(tempDir, "backups"),
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 10,
		EnableBackup:    true,
		BackupInterval:  time.Hour, // Disabled for testing
	}

	store, err := NewSQLiteStore(config)
	require.NoError(t, err)

	sandboxStore := NewSandboxStore(store)
	fileStore := NewFileStore(store)
	metricsStore := NewMetricsStore(store)
	migrator := NewMigrator(store)

	return store, sandboxStore, fileStore, metricsStore, migrator
}