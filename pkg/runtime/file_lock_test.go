package runtime

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNewFileLockManager(t *testing.T) {
	flm := NewFileLockManager()
	if flm == nil {
		t.Fatal("NewFileLockManager returned nil")
	}

	if flm.locks == nil {
		t.Error("locks map not initialized")
	}

	if flm.locksByID == nil {
		t.Error("locksByID map not initialized")
	}

	// Clean up
	flm.Shutdown()
}

func TestAcquireLock(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "test-container"
	filePath := "/workspace/test.txt"
	timeout := 5 * time.Second

	// Test acquiring a new lock
	lockID, err := flm.AcquireLock(ctx, containerID, filePath, timeout)
	if err != nil {
		t.Fatalf("Failed to acquire lock: %v", err)
	}

	if lockID == "" {
		t.Error("Lock ID is empty")
	}

	// Verify lock is active
	if !flm.IsLocked(containerID, filePath) {
		t.Error("File should be locked")
	}

	// Test acquiring same lock again (should wait and timeout)
	ctx2, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = flm.AcquireLock(ctx2, containerID, filePath, timeout)
	if err == nil {
		t.Error("Expected timeout error when acquiring already locked file")
	}

	// Release the lock
	err = flm.ReleaseLock(containerID, filePath, lockID)
	if err != nil {
		t.Errorf("Failed to release lock: %v", err)
	}

	// Verify lock is released
	if flm.IsLocked(containerID, filePath) {
		t.Error("File should not be locked after release")
	}
}

func TestAcquireLockWithType(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "test-container"
	filePath := "/workspace/test.txt"
	timeout := 5 * time.Second

	// Test read lock
	readLockID, err := flm.AcquireLockWithType(ctx, containerID, filePath, LockTypeRead, timeout)
	if err != nil {
		t.Fatalf("Failed to acquire read lock: %v", err)
	}

	// Test acquiring another read lock (should succeed)
	readLockID2, err := flm.AcquireLockWithType(ctx, containerID, filePath, LockTypeRead, timeout)
	if err != nil {
		t.Errorf("Failed to acquire second read lock: %v", err)
	}

	// Both should return the same lock ID for read locks
	if readLockID != readLockID2 {
		t.Error("Read locks should reuse the same lock ID")
	}

	// Release read lock
	err = flm.ReleaseLock(containerID, filePath, readLockID)
	if err != nil {
		t.Errorf("Failed to release read lock: %v", err)
	}

	// Test write lock
	writeLockID, err := flm.AcquireLockWithType(ctx, containerID, filePath, LockTypeWrite, timeout)
	if err != nil {
		t.Fatalf("Failed to acquire write lock: %v", err)
	}

	// Test acquiring read lock when write lock exists (should fail)
	ctx2, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = flm.AcquireLockWithType(ctx2, containerID, filePath, LockTypeRead, timeout)
	if err == nil {
		t.Error("Expected timeout when acquiring read lock with active write lock")
	}

	// Release write lock
	err = flm.ReleaseLock(containerID, filePath, writeLockID)
	if err != nil {
		t.Errorf("Failed to release write lock: %v", err)
	}
}

func TestReleaseLock(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "test-container"
	filePath := "/workspace/test.txt"
	timeout := 5 * time.Second

	// Acquire lock
	lockID, err := flm.AcquireLock(ctx, containerID, filePath, timeout)
	if err != nil {
		t.Fatalf("Failed to acquire lock: %v", err)
	}

	// Test releasing with correct lock ID
	err = flm.ReleaseLock(containerID, filePath, lockID)
	if err != nil {
		t.Errorf("Failed to release lock: %v", err)
	}

	// Test releasing non-existent lock
	err = flm.ReleaseLock(containerID, "/workspace/missing.txt", "fake-lock")
	if err == nil {
		t.Error("Expected error when releasing non-existent lock")
	}

	// Test releasing with wrong lock ID
	lockID2, _ := flm.AcquireLock(ctx, containerID, filePath, timeout)
	err = flm.ReleaseLock(containerID, filePath, "wrong-id")
	if err == nil {
		t.Error("Expected error when releasing with wrong lock ID")
	}

	// Clean up
	flm.ReleaseLock(containerID, filePath, lockID2)
}

func TestExtendLock(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "test-container"
	filePath := "/workspace/test.txt"
	timeout := 1 * time.Second

	// Acquire lock
	lockID, err := flm.AcquireLock(ctx, containerID, filePath, timeout)
	if err != nil {
		t.Fatalf("Failed to acquire lock: %v", err)
	}

	// Get original expiry time
	info, err := flm.GetLockInfo(containerID, filePath)
	if err != nil {
		t.Fatalf("Failed to get lock info: %v", err)
	}
	originalExpiry := info.ExpiresAt

	// Extend lock
	extension := 2 * time.Second
	err = flm.ExtendLock(lockID, extension)
	if err != nil {
		t.Errorf("Failed to extend lock: %v", err)
	}

	// Get new expiry time
	info, err = flm.GetLockInfo(containerID, filePath)
	if err != nil {
		t.Fatalf("Failed to get lock info after extension: %v", err)
	}

	expectedExpiry := originalExpiry.Add(extension)
	if !info.ExpiresAt.Equal(expectedExpiry) {
		t.Errorf("Lock expiry not extended correctly. Expected: %v, Got: %v", expectedExpiry, info.ExpiresAt)
	}

	// Test extending non-existent lock
	err = flm.ExtendLock("fake-lock-id", extension)
	if err == nil {
		t.Error("Expected error when extending non-existent lock")
	}

	// Clean up
	flm.ReleaseLock(containerID, filePath, lockID)
}

func TestIsLocked(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "test-container"
	filePath := "/workspace/test.txt"
	timeout := 5 * time.Second

	// Test unlocked file
	if flm.IsLocked(containerID, filePath) {
		t.Error("File should not be locked initially")
	}

	// Acquire lock
	lockID, err := flm.AcquireLock(ctx, containerID, filePath, timeout)
	if err != nil {
		t.Fatalf("Failed to acquire lock: %v", err)
	}

	// Test locked file
	if !flm.IsLocked(containerID, filePath) {
		t.Error("File should be locked")
	}

	// Release lock
	flm.ReleaseLock(containerID, filePath, lockID)

	// Test unlocked file after release
	if flm.IsLocked(containerID, filePath) {
		t.Error("File should not be locked after release")
	}
}

func TestGetLockInfo(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "test-container"
	filePath := "/workspace/test.txt"
	timeout := 5 * time.Second

	// Test getting info for non-existent lock
	_, err := flm.GetLockInfo(containerID, filePath)
	if err == nil {
		t.Error("Expected error for non-existent lock")
	}

	// Acquire lock
	lockID, err := flm.AcquireLock(ctx, containerID, filePath, timeout)
	if err != nil {
		t.Fatalf("Failed to acquire lock: %v", err)
	}

	// Get lock info
	info, err := flm.GetLockInfo(containerID, filePath)
	if err != nil {
		t.Fatalf("Failed to get lock info: %v", err)
	}

	if info.ID != lockID {
		t.Errorf("Expected lock ID %s, got %s", lockID, info.ID)
	}

	if info.ContainerID != containerID {
		t.Errorf("Expected container ID %s, got %s", containerID, info.ContainerID)
	}

	if info.FilePath != filePath {
		t.Errorf("Expected file path %s, got %s", filePath, info.FilePath)
	}

	if info.LockType != LockTypeWrite {
		t.Errorf("Expected lock type %s, got %s", LockTypeWrite, info.LockType)
	}

	// Clean up
	flm.ReleaseLock(containerID, filePath, lockID)
}

func TestListLocks(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "test-container"
	timeout := 5 * time.Second

	// Test empty list
	locks := flm.ListLocks(containerID)
	if len(locks) != 0 {
		t.Error("Expected empty lock list initially")
	}

	// Acquire multiple locks
	lockID1, err := flm.AcquireLock(ctx, containerID, "/workspace/file1.txt", timeout)
	if err != nil {
		t.Fatalf("Failed to acquire first lock: %v", err)
	}

	lockID2, err := flm.AcquireLock(ctx, containerID, "/workspace/file2.txt", timeout)
	if err != nil {
		t.Fatalf("Failed to acquire second lock: %v", err)
	}

	// List locks
	locks = flm.ListLocks(containerID)
	if len(locks) != 2 {
		t.Errorf("Expected 2 locks, got %d", len(locks))
	}

	// Acquire lock for different container
	lockID3, err := flm.AcquireLock(ctx, "other-container", "/workspace/file3.txt", timeout)
	if err != nil {
		t.Fatalf("Failed to acquire third lock: %v", err)
	}

	// List locks for original container (should still be 2)
	locks = flm.ListLocks(containerID)
	if len(locks) != 2 {
		t.Errorf("Expected 2 locks for container %s, got %d", containerID, len(locks))
	}

	// List locks for other container (should be 1)
	locks = flm.ListLocks("other-container")
	if len(locks) != 1 {
		t.Errorf("Expected 1 lock for other-container, got %d", len(locks))
	}

	// Clean up
	flm.ReleaseLock(containerID, "/workspace/file1.txt", lockID1)
	flm.ReleaseLock(containerID, "/workspace/file2.txt", lockID2)
	flm.ReleaseLock("other-container", "/workspace/file3.txt", lockID3)
}

func TestReleaseAllLocks(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "test-container"
	timeout := 5 * time.Second

	// Acquire multiple locks
	_, err := flm.AcquireLock(ctx, containerID, "/workspace/file1.txt", timeout)
	if err != nil {
		t.Fatalf("Failed to acquire first lock: %v", err)
	}

	_, err = flm.AcquireLock(ctx, containerID, "/workspace/file2.txt", timeout)
	if err != nil {
		t.Fatalf("Failed to acquire second lock: %v", err)
	}

	// Acquire lock for different container
	_, err = flm.AcquireLock(ctx, "other-container", "/workspace/file3.txt", timeout)
	if err != nil {
		t.Fatalf("Failed to acquire third lock: %v", err)
	}

	// Release all locks for test-container
	err = flm.ReleaseAllLocks(containerID)
	if err != nil {
		t.Errorf("Failed to release all locks: %v", err)
	}

	// Verify locks are released for test-container
	locks := flm.ListLocks(containerID)
	if len(locks) != 0 {
		t.Errorf("Expected 0 locks after release all, got %d", len(locks))
	}

	// Verify locks still exist for other-container
	locks = flm.ListLocks("other-container")
	if len(locks) != 1 {
		t.Errorf("Expected 1 lock for other-container, got %d", len(locks))
	}

	// Clean up remaining locks
	flm.ReleaseAllLocks("other-container")
}

func TestTryLock(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	containerID := "test-container"
	filePath := "/workspace/test.txt"
	duration := 5 * time.Second

	// Test try lock on unlocked file
	lockID, err := flm.TryLock(containerID, filePath, LockTypeWrite, duration)
	if err != nil {
		t.Errorf("TryLock failed on unlocked file: %v", err)
	}

	// Test try lock on locked file (should fail quickly)
	_, err = flm.TryLock(containerID, filePath, LockTypeWrite, duration)
	if err == nil {
		t.Error("Expected TryLock to fail on locked file")
	}

	// Clean up
	flm.ReleaseLock(containerID, filePath, lockID)
}

func TestExpiredLockCleanup(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "test-container"
	filePath := "/workspace/test.txt"
	timeout := 100 * time.Millisecond // Very short timeout

	// Acquire lock with short timeout
	lockID, err := flm.AcquireLock(ctx, containerID, filePath, timeout)
	if err != nil {
		t.Fatalf("Failed to acquire lock: %v", err)
	}

	// Verify lock is active
	if !flm.IsLocked(containerID, filePath) {
		t.Error("File should be locked")
	}

	// Wait for lock to expire
	time.Sleep(200 * time.Millisecond)

	// Trigger cleanup
	flm.TriggerCleanup()
	time.Sleep(50 * time.Millisecond) // Give cleanup time to run

	// Verify lock is no longer active
	if flm.IsLocked(containerID, filePath) {
		t.Error("File should not be locked after expiry")
	}

	// Verify we can't release expired lock
	err = flm.ReleaseLock(containerID, filePath, lockID)
	if err == nil {
		t.Error("Expected error when releasing expired lock")
	}
}

func TestWithLock(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "test-container"
	filePath := "/workspace/test.txt"
	timeout := 5 * time.Second

	executed := false

	err := flm.WithLock(ctx, containerID, filePath, LockTypeWrite, timeout, func() error {
		// Verify file is locked during execution
		if !flm.IsLocked(containerID, filePath) {
			t.Error("File should be locked during WithLock execution")
		}
		executed = true
		return nil
	})

	if err != nil {
		t.Errorf("WithLock failed: %v", err)
	}

	if !executed {
		t.Error("Function was not executed")
	}

	// Verify lock is released after execution
	if flm.IsLocked(containerID, filePath) {
		t.Error("File should not be locked after WithLock completion")
	}
}

func TestLockGuard(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "test-container"
	filePath := "/workspace/test.txt"
	timeout := 5 * time.Second

	// Create lock guard
	guard, err := flm.NewLockGuard(ctx, containerID, filePath, LockTypeWrite, timeout)
	if err != nil {
		t.Fatalf("Failed to create lock guard: %v", err)
	}

	// Verify file is locked
	if !flm.IsLocked(containerID, filePath) {
		t.Error("File should be locked by guard")
	}

	// Test guard properties
	if guard.IsReleased() {
		t.Error("Guard should not be released initially")
	}

	// Test extend
	err = guard.Extend(2 * time.Second)
	if err != nil {
		t.Errorf("Failed to extend guard lock: %v", err)
	}

	// Release guard
	err = guard.Release()
	if err != nil {
		t.Errorf("Failed to release guard: %v", err)
	}

	// Verify guard is released
	if !guard.IsReleased() {
		t.Error("Guard should be released")
	}

	// Verify file is unlocked
	if flm.IsLocked(containerID, filePath) {
		t.Error("File should not be locked after guard release")
	}

	// Test double release
	err = guard.Release()
	if err == nil {
		t.Error("Expected error on double release")
	}

	// Test extend after release
	err = guard.Extend(1 * time.Second)
	if err == nil {
		t.Error("Expected error when extending released guard")
	}
}

func TestConcurrentLocking(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	containerID := "test-container"
	filePath := "/workspace/concurrent.txt"
	timeout := 1 * time.Second
	numGoroutines := 10

	var wg sync.WaitGroup
	var mu sync.Mutex
	successCount := 0

	// Try to acquire locks concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			lockID, err := flm.AcquireLock(ctx, containerID, filePath, timeout)
			if err == nil {
				mu.Lock()
				successCount++
				mu.Unlock()

				// Hold the lock briefly
				time.Sleep(10 * time.Millisecond)

				// Release the lock
				flm.ReleaseLock(containerID, filePath, lockID)
			}
		}(i)
	}

	wg.Wait()

	// Only one goroutine should have successfully acquired the lock initially
	if successCount == 0 {
		t.Error("No goroutine successfully acquired the lock")
	}

	// All locks should be released now
	if flm.IsLocked(containerID, filePath) {
		t.Error("File should not be locked after all goroutines complete")
	}
}

func TestGetStats(t *testing.T) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "test-container"
	timeout := 5 * time.Second

	// Initial stats
	stats := flm.GetStats()
	if stats["total_locks"].(int) != 0 {
		t.Error("Expected 0 total locks initially")
	}

	// Acquire some locks
	lockID1, _ := flm.AcquireLockWithType(ctx, containerID, "/workspace/file1.txt", LockTypeRead, timeout)
	lockID2, _ := flm.AcquireLockWithType(ctx, containerID, "/workspace/file2.txt", LockTypeWrite, timeout)

	// Check stats
	stats = flm.GetStats()
	if stats["total_locks"].(int) != 2 {
		t.Errorf("Expected 2 total locks, got %d", stats["total_locks"].(int))
	}

	if stats["read_locks"].(int) != 1 {
		t.Errorf("Expected 1 read lock, got %d", stats["read_locks"].(int))
	}

	if stats["write_locks"].(int) != 1 {
		t.Errorf("Expected 1 write lock, got %d", stats["write_locks"].(int))
	}

	// Clean up
	flm.ReleaseLock(containerID, "/workspace/file1.txt", lockID1)
	flm.ReleaseLock(containerID, "/workspace/file2.txt", lockID2)
}

// Benchmark tests

func BenchmarkAcquireLock(b *testing.B) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "bench-container"
	timeout := 5 * time.Second

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filePath := "/workspace/bench" + string(rune(i%1000)) + ".txt"
		lockID, err := flm.AcquireLock(ctx, containerID, filePath, timeout)
		if err != nil {
			b.Fatal(err)
		}
		flm.ReleaseLock(containerID, filePath, lockID)
	}
}

func BenchmarkIsLocked(b *testing.B) {
	flm := NewFileLockManager()
	defer flm.Shutdown()

	ctx := context.Background()
	containerID := "bench-container"
	filePath := "/workspace/bench.txt"
	timeout := 5 * time.Second

	// Acquire a lock
	lockID, _ := flm.AcquireLock(ctx, containerID, filePath, timeout)
	defer flm.ReleaseLock(containerID, filePath, lockID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		flm.IsLocked(containerID, filePath)
	}
}