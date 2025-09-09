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

func TestSandboxStore_Create(t *testing.T) {
	store, sandboxStore := setupTestSandboxStore(t)
	defer store.Close()

	ctx := context.Background()
	now := time.Now()

	state := &SandboxState{
		ID:          "test-sandbox-1",
		ContainerID: "container-123",
		Status:      "running",
		WorkingDir:  "/workspace",
		Environment: map[string]string{"TEST": "value"},
		CreatedAt:   now,
		UpdatedAt:   now,
		Config: map[string]interface{}{
			"image": "ubuntu:20.04",
		},
		Metadata: map[string]interface{}{
			"owner": "test-user",
		},
		Version: 1,
	}

	err := sandboxStore.Create(ctx, state)
	require.NoError(t, err)
	assert.Greater(t, state.ID, "")

	// Verify the sandbox was created
	retrieved, err := sandboxStore.Get(ctx, state.ID)
	require.NoError(t, err)
	assert.Equal(t, state.ID, retrieved.ID)
	assert.Equal(t, state.Status, retrieved.Status)
	assert.Equal(t, state.Environment["TEST"], retrieved.Environment["TEST"])
	assert.Equal(t, state.Config["image"], retrieved.Config["image"])
	assert.Equal(t, state.Metadata["owner"], retrieved.Metadata["owner"])
}

func TestSandboxStore_Get(t *testing.T) {
	store, sandboxStore := setupTestSandboxStore(t)
	defer store.Close()

	ctx := context.Background()

	// Test getting non-existent sandbox
	_, err := sandboxStore.Get(ctx, "non-existent")
	assert.Error(t, err)

	// Create a sandbox
	state := createTestSandbox(t, sandboxStore, "test-get")

	// Get the sandbox
	retrieved, err := sandboxStore.Get(ctx, state.ID)
	require.NoError(t, err)
	assert.Equal(t, state.ID, retrieved.ID)
	assert.Equal(t, state.Status, retrieved.Status)
}

func TestSandboxStore_Update(t *testing.T) {
	store, sandboxStore := setupTestSandboxStore(t)
	defer store.Close()

	ctx := context.Background()

	// Create a sandbox
	state := createTestSandbox(t, sandboxStore, "test-update")

	// Update the sandbox
	state.Status = "stopped"
	state.Environment["NEW_VAR"] = "new_value"
	state.Metadata["updated"] = true

	err := sandboxStore.Update(ctx, state)
	require.NoError(t, err)
	assert.Equal(t, 2, state.Version) // Version should increment

	// Verify the update
	retrieved, err := sandboxStore.Get(ctx, state.ID)
	require.NoError(t, err)
	assert.Equal(t, "stopped", retrieved.Status)
	assert.Equal(t, "new_value", retrieved.Environment["NEW_VAR"])
	assert.Equal(t, true, retrieved.Metadata["updated"])
	assert.Equal(t, 2, retrieved.Version)
}

func TestSandboxStore_UpdateOptimisticLocking(t *testing.T) {
	store, sandboxStore := setupTestSandboxStore(t)
	defer store.Close()

	ctx := context.Background()

	// Create a sandbox
	state := createTestSandbox(t, sandboxStore, "test-optimistic")

	// Create two copies with the same version
	state1 := *state
	state2 := *state

	// Update first copy
	state1.Status = "stopped"
	err := sandboxStore.Update(ctx, &state1)
	require.NoError(t, err)

	// Try to update second copy (should fail due to version mismatch)
	state2.Status = "error"
	err = sandboxStore.Update(ctx, &state2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version mismatch")
}

func TestSandboxStore_Delete(t *testing.T) {
	store, sandboxStore := setupTestSandboxStore(t)
	defer store.Close()

	ctx := context.Background()

	// Create a sandbox
	state := createTestSandbox(t, sandboxStore, "test-delete")

	// Delete the sandbox
	err := sandboxStore.Delete(ctx, state.ID, "test-user")
	require.NoError(t, err)

	// Verify the sandbox is soft-deleted
	_, err = sandboxStore.Get(ctx, state.ID)
	assert.Error(t, err)

	// Try to delete again (should fail)
	err = sandboxStore.Delete(ctx, state.ID, "test-user")
	assert.Error(t, err)
}

func TestSandboxStore_List(t *testing.T) {
	store, sandboxStore := setupTestSandboxStore(t)
	defer store.Close()

	ctx := context.Background()

	// Create multiple sandboxes
	createTestSandbox(t, sandboxStore, "test-list-1")
	createTestSandbox(t, sandboxStore, "test-list-2")
	state3 := createTestSandbox(t, sandboxStore, "test-list-3")

	// Update one to have different status
	state3.Status = "stopped"
	err := sandboxStore.Update(ctx, state3)
	require.NoError(t, err)

	t.Run("list all", func(t *testing.T) {
		sandboxes, err := sandboxStore.List(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(sandboxes), 3)
	})

	t.Run("filter by status", func(t *testing.T) {
		filter := &SandboxFilter{
			Status: "stopped",
		}
		sandboxes, err := sandboxStore.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(sandboxes), 1)
		for _, sb := range sandboxes {
			assert.Equal(t, "stopped", sb.Status)
		}
	})

	t.Run("filter by created after", func(t *testing.T) {
		filter := &SandboxFilter{
			CreatedAfter: time.Now().Add(-time.Hour),
		}
		sandboxes, err := sandboxStore.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(sandboxes), 3)
	})

	t.Run("limit results", func(t *testing.T) {
		filter := &SandboxFilter{
			Limit: 2,
		}
		sandboxes, err := sandboxStore.List(ctx, filter)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(sandboxes), 2)
	})
}

func TestSandboxStore_Recover(t *testing.T) {
	store, sandboxStore := setupTestSandboxStore(t)
	defer store.Close()

	ctx := context.Background()

	// Create and delete a sandbox
	state := createTestSandbox(t, sandboxStore, "test-recover")
	err := sandboxStore.Delete(ctx, state.ID, "test-user")
	require.NoError(t, err)

	// Recover the sandbox
	err = sandboxStore.Recover(ctx, state.ID, "recovery-user")
	require.NoError(t, err)

	// Verify the sandbox is recovered
	recovered, err := sandboxStore.Get(ctx, state.ID)
	require.NoError(t, err)
	assert.Equal(t, state.ID, recovered.ID)
	assert.Nil(t, recovered.DeletedAt)

	// Try to recover again (should fail)
	err = sandboxStore.Recover(ctx, state.ID, "recovery-user")
	assert.Error(t, err)
}

func TestSandboxStore_CreateCheckpoint(t *testing.T) {
	store, sandboxStore := setupTestSandboxStore(t)
	defer store.Close()

	ctx := context.Background()

	// Create a sandbox
	state := createTestSandbox(t, sandboxStore, "test-checkpoint")

	// Create checkpoint
	checkpointData := map[string]interface{}{
		"process_count": float64(5), // JSON unmarshaling converts to float64
		"memory_usage":  "100MB",
	}
	err := sandboxStore.CreateCheckpoint(ctx, state.ID, "manual backup", checkpointData)
	require.NoError(t, err)

	// Verify checkpoint data
	updated, err := sandboxStore.Get(ctx, state.ID)
	require.NoError(t, err)
	assert.NotNil(t, updated.RecoveryData)
	assert.Equal(t, "manual backup", updated.RecoveryData["checkpoint_reason"])
	assert.NotNil(t, updated.RecoveryData["checkpoint_time"])
	assert.Equal(t, checkpointData, updated.RecoveryData["checkpoint_data"])
}

func TestSandboxStore_GetAuditTrail(t *testing.T) {
	store, sandboxStore := setupTestSandboxStore(t)
	defer store.Close()

	ctx := context.Background()

	// Create a sandbox (creates audit entry)
	state := createTestSandbox(t, sandboxStore, "test-audit")

	// Update the sandbox (creates another audit entry)
	state.Status = "stopped"
	err := sandboxStore.Update(ctx, state)
	require.NoError(t, err)

	// Delete the sandbox (creates third audit entry)
	err = sandboxStore.Delete(ctx, state.ID, "test-user")
	require.NoError(t, err)

	// Get audit trail
	entries, err := sandboxStore.GetAuditTrail(ctx, state.ID, 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 3)

	// Check audit entries are in reverse chronological order
	if len(entries) >= 2 {
		assert.True(t, entries[0].Timestamp.After(entries[1].Timestamp) || entries[0].Timestamp.Equal(entries[1].Timestamp))
	}

	// Verify audit entry content
	var deleteEntry *AuditEntry
	for _, entry := range entries {
		if entry.Action == "delete" {
			deleteEntry = entry
			break
		}
	}
	require.NotNil(t, deleteEntry)
	assert.Equal(t, "sandbox", deleteEntry.EntityType)
	assert.Equal(t, state.ID, deleteEntry.EntityID)
	assert.Equal(t, "test-user", deleteEntry.UserID)
}

func TestSandboxStore_CleanupDeleted(t *testing.T) {
	store, sandboxStore := setupTestSandboxStore(t)
	defer store.Close()

	ctx := context.Background()

	// Create and delete sandboxes
	state1 := createTestSandbox(t, sandboxStore, "test-cleanup-1")
	state2 := createTestSandbox(t, sandboxStore, "test-cleanup-2")

	err := sandboxStore.Delete(ctx, state1.ID, "test-user")
	require.NoError(t, err)

	err = sandboxStore.Delete(ctx, state2.ID, "test-user")
	require.NoError(t, err)

	// Clean up deleted sandboxes (use 0 days to delete immediately)
	deletedCount, err := sandboxStore.CleanupDeleted(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), deletedCount)

	// Verify sandboxes are permanently deleted
	err = sandboxStore.Recover(ctx, state1.ID, "test-user")
	assert.Error(t, err)

	err = sandboxStore.Recover(ctx, state2.ID, "test-user")
	assert.Error(t, err)
}

func TestSandboxStore_ConcurrentUpdates(t *testing.T) {
	store, sandboxStore := setupTestSandboxStore(t)
	defer store.Close()

	ctx := context.Background()

	// Create a sandbox
	state := createTestSandbox(t, sandboxStore, "test-concurrent")

	concurrency := 10
	done := make(chan error, concurrency)

	// Attempt concurrent updates
	for i := 0; i < concurrency; i++ {
		go func(id int) {
			// Get current state
			currentState, err := sandboxStore.Get(ctx, state.ID)
			if err != nil {
				done <- err
				return
			}

			// Modify state
			currentState.Metadata[fmt.Sprintf("concurrent_%d", id)] = true

			// Try to update
			err = sandboxStore.Update(ctx, currentState)
			done <- err
		}(i)
	}

	// Collect results
	var successCount, errorCount int
	for i := 0; i < concurrency; i++ {
		err := <-done
		if err != nil {
			errorCount++
		} else {
			successCount++
		}
	}

	// Only one update should succeed due to optimistic locking
	assert.Equal(t, 1, successCount)
	assert.Equal(t, concurrency-1, errorCount)
}

func TestSandboxStore_ErrorCases(t *testing.T) {
	store, sandboxStore := setupTestSandboxStore(t)
	defer store.Close()

	ctx := context.Background()

	t.Run("create with empty ID", func(t *testing.T) {
		state := &SandboxState{
			ID:     "",
			Status: "running",
		}
		err := sandboxStore.Create(ctx, state)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ID cannot be empty")
	})

	t.Run("get with empty ID", func(t *testing.T) {
		_, err := sandboxStore.Get(ctx, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ID cannot be empty")
	})

	t.Run("update non-existent sandbox", func(t *testing.T) {
		state := &SandboxState{
			ID:      "non-existent",
			Status:  "running",
			Version: 1,
		}
		err := sandboxStore.Update(ctx, state)
		assert.Error(t, err)
	})

	t.Run("delete non-existent sandbox", func(t *testing.T) {
		err := sandboxStore.Delete(ctx, "non-existent", "test-user")
		assert.Error(t, err)
	})
}

// setupTestSandboxStore creates a test sandbox store
func setupTestSandboxStore(t *testing.T) (*SQLiteStore, *SandboxStore) {
	tempDir, err := os.MkdirTemp("", "sandbox_store_test")
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
		EnableBackup:    false,
	}

	store, err := NewSQLiteStore(config)
	require.NoError(t, err)

	sandboxStore := NewSandboxStore(store)
	return store, sandboxStore
}

// createTestSandbox creates a test sandbox state
func createTestSandbox(t *testing.T, sandboxStore *SandboxStore, id string) *SandboxState {
	ctx := context.Background()
	now := time.Now()

	state := &SandboxState{
		ID:          id,
		ContainerID: fmt.Sprintf("container-%s", id),
		Status:      "running",
		WorkingDir:  "/workspace",
		Environment: map[string]string{"TEST": "value"},
		CreatedAt:   now,
		UpdatedAt:   now,
		Config: map[string]interface{}{
			"image": "ubuntu:20.04",
		},
		Metadata: map[string]interface{}{
			"owner": "test-user",
		},
		Version: 1,
	}

	err := sandboxStore.Create(ctx, state)
	require.NoError(t, err)

	return state
}

func BenchmarkSandboxStore_Create(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "sandbox_store_bench")
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

	sandboxStore := NewSandboxStore(store)
	ctx := context.Background()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		state := &SandboxState{
			ID:          fmt.Sprintf("bench-create-%d", i),
			ContainerID: fmt.Sprintf("container-%d", i),
			Status:      "running",
			WorkingDir:  "/workspace",
			Environment: map[string]string{"TEST": "value"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Config: map[string]interface{}{
				"image": "ubuntu:20.04",
			},
			Metadata: map[string]interface{}{
				"owner": "bench-user",
			},
			Version: 1,
		}

		err := sandboxStore.Create(ctx, state)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSandboxStore_Get(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "sandbox_store_bench")
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

	sandboxStore := NewSandboxStore(store)
	ctx := context.Background()

	// Create test data
	testIDs := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		testIDs[i] = fmt.Sprintf("bench-get-%d", i)
		state := &SandboxState{
			ID:          testIDs[i],
			ContainerID: fmt.Sprintf("container-%d", i),
			Status:      "running",
			WorkingDir:  "/workspace",
			Environment: map[string]string{"TEST": "value"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Config: map[string]interface{}{
				"image": "ubuntu:20.04",
			},
			Metadata: map[string]interface{}{
				"owner": "bench-user",
			},
			Version: 1,
		}

		err := sandboxStore.Create(ctx, state)
		require.NoError(b, err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := sandboxStore.Get(ctx, testIDs[i%1000])
		if err != nil {
			b.Fatal(err)
		}
	}
}