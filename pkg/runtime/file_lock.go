package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// FileLock represents a file lock entry
type FileLock struct {
	ID          string    `json:"id"`
	ContainerID string    `json:"container_id"`
	FilePath    string    `json:"file_path"`
	AcquiredAt  time.Time `json:"acquired_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	LockType    LockType  `json:"lock_type"`
}

// LockType defines the type of file lock
type LockType string

const (
	LockTypeRead  LockType = "read"
	LockTypeWrite LockType = "write"
)

// FileLockManager manages file locks to prevent concurrent access
type FileLockManager struct {
	locks    map[string]*FileLock // key: containerID:filePath
	locksByID map[string]*FileLock // key: lockID
	mu       sync.RWMutex
	cleanup  chan struct{}
	done     chan struct{}
}

// NewFileLockManager creates a new file lock manager
func NewFileLockManager() *FileLockManager {
	flm := &FileLockManager{
		locks:     make(map[string]*FileLock),
		locksByID: make(map[string]*FileLock),
		cleanup:   make(chan struct{}, 1),
		done:      make(chan struct{}),
	}

	// Start cleanup goroutine
	go flm.cleanupExpiredLocks()

	return flm
}

// AcquireLock acquires a lock on a file with timeout
func (flm *FileLockManager) AcquireLock(ctx context.Context, containerID, filePath string, timeout time.Duration) (string, error) {
	return flm.AcquireLockWithType(ctx, containerID, filePath, LockTypeWrite, timeout)
}

// AcquireLockWithType acquires a lock with specified type
func (flm *FileLockManager) AcquireLockWithType(ctx context.Context, containerID, filePath string, lockType LockType, timeout time.Duration) (string, error) {
	lockKey := fmt.Sprintf("%s:%s", containerID, filePath)
	lockID := generateLockID(containerID, filePath)

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return "", fmt.Errorf("lock acquisition timeout for file %s in container %s", filePath, containerID)
			}

			flm.mu.Lock()

			// Check if lock exists and is still valid
			existingLock, exists := flm.locks[lockKey]
			if exists {
				// Check if lock is expired
				if time.Now().After(existingLock.ExpiresAt) {
					// Remove expired lock
					delete(flm.locks, lockKey)
					delete(flm.locksByID, existingLock.ID)
					exists = false
				} else {
					// Lock still valid - check compatibility
					if lockType == LockTypeRead && existingLock.LockType == LockTypeRead {
						// Multiple read locks are allowed
						flm.mu.Unlock()
						return existingLock.ID, nil
					}
					// Write lock or read-write conflict
					flm.mu.Unlock()
					continue
				}
			}

			if !exists {
				// Create new lock
				lock := &FileLock{
					ID:          lockID,
					ContainerID: containerID,
					FilePath:    filePath,
					AcquiredAt:  time.Now(),
					ExpiresAt:   time.Now().Add(timeout),
					LockType:    lockType,
				}

				flm.locks[lockKey] = lock
				flm.locksByID[lockID] = lock

				log.Debug().
					Str("container_id", containerID).
					Str("file_path", filePath).
					Str("lock_id", lockID).
					Str("lock_type", string(lockType)).
					Dur("timeout", timeout).
					Msg("File lock acquired")

				flm.mu.Unlock()
				return lockID, nil
			}

			flm.mu.Unlock()
		}
	}
}

// ReleaseLock releases a file lock
func (flm *FileLockManager) ReleaseLock(containerID, filePath, lockID string) error {
	lockKey := fmt.Sprintf("%s:%s", containerID, filePath)

	flm.mu.Lock()
	defer flm.mu.Unlock()

	lock, exists := flm.locks[lockKey]
	if !exists {
		return fmt.Errorf("no lock found for file %s in container %s", filePath, containerID)
	}

	if lock.ID != lockID {
		return fmt.Errorf("invalid lock ID %s for file %s in container %s", lockID, filePath, containerID)
	}

	delete(flm.locks, lockKey)
	delete(flm.locksByID, lockID)

	log.Debug().
		Str("container_id", containerID).
		Str("file_path", filePath).
		Str("lock_id", lockID).
		Msg("File lock released")

	return nil
}

// ExtendLock extends the expiration time of a lock
func (flm *FileLockManager) ExtendLock(lockID string, extension time.Duration) error {
	flm.mu.Lock()
	defer flm.mu.Unlock()

	lock, exists := flm.locksByID[lockID]
	if !exists {
		return fmt.Errorf("lock with ID %s not found", lockID)
	}

	// Check if lock is already expired
	if time.Now().After(lock.ExpiresAt) {
		return fmt.Errorf("cannot extend expired lock %s", lockID)
	}

	lock.ExpiresAt = lock.ExpiresAt.Add(extension)

	log.Debug().
		Str("lock_id", lockID).
		Dur("extension", extension).
		Time("new_expiry", lock.ExpiresAt).
		Msg("File lock extended")

	return nil
}

// IsLocked checks if a file is currently locked
func (flm *FileLockManager) IsLocked(containerID, filePath string) bool {
	lockKey := fmt.Sprintf("%s:%s", containerID, filePath)

	flm.mu.RLock()
	defer flm.mu.RUnlock()

	lock, exists := flm.locks[lockKey]
	if !exists {
		return false
	}

	// Check if lock is expired
	if time.Now().After(lock.ExpiresAt) {
		return false
	}

	return true
}

// GetLockInfo returns information about a lock
func (flm *FileLockManager) GetLockInfo(containerID, filePath string) (*FileLock, error) {
	lockKey := fmt.Sprintf("%s:%s", containerID, filePath)

	flm.mu.RLock()
	defer flm.mu.RUnlock()

	lock, exists := flm.locks[lockKey]
	if !exists {
		return nil, fmt.Errorf("no lock found for file %s in container %s", filePath, containerID)
	}

	// Check if lock is expired
	if time.Now().After(lock.ExpiresAt) {
		return nil, fmt.Errorf("lock for file %s in container %s has expired", filePath, containerID)
	}

	// Return a copy to prevent external modification
	lockCopy := *lock
	return &lockCopy, nil
}

// ListLocks returns all active locks for a container
func (flm *FileLockManager) ListLocks(containerID string) []*FileLock {
	flm.mu.RLock()
	defer flm.mu.RUnlock()

	var locks []*FileLock
	now := time.Now()

	for _, lock := range flm.locks {
		if lock.ContainerID == containerID && now.Before(lock.ExpiresAt) {
			lockCopy := *lock
			locks = append(locks, &lockCopy)
		}
	}

	return locks
}

// ReleaseAllLocks releases all locks for a container
func (flm *FileLockManager) ReleaseAllLocks(containerID string) error {
	flm.mu.Lock()
	defer flm.mu.Unlock()

	var releasedCount int
	var keysToDelete []string

	// Find all locks for the container
	for key, lock := range flm.locks {
		if lock.ContainerID == containerID {
			keysToDelete = append(keysToDelete, key)
			delete(flm.locksByID, lock.ID)
			releasedCount++
		}
	}

	// Delete the locks
	for _, key := range keysToDelete {
		delete(flm.locks, key)
	}

	log.Info().
		Str("container_id", containerID).
		Int("released_count", releasedCount).
		Msg("Released all locks for container")

	return nil
}

// TryLock attempts to acquire a lock without waiting
func (flm *FileLockManager) TryLock(containerID, filePath string, lockType LockType, duration time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	return flm.AcquireLockWithType(ctx, containerID, filePath, lockType, duration)
}

// cleanupExpiredLocks periodically removes expired locks
func (flm *FileLockManager) cleanupExpiredLocks() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			flm.performCleanup()
		case <-flm.cleanup:
			flm.performCleanup()
		case <-flm.done:
			return
		}
	}
}

// performCleanup removes expired locks
func (flm *FileLockManager) performCleanup() {
	flm.mu.Lock()
	defer flm.mu.Unlock()

	now := time.Now()
	var expiredKeys []string
	var expiredIDs []string

	for key, lock := range flm.locks {
		if now.After(lock.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
			expiredIDs = append(expiredIDs, lock.ID)
		}
	}

	for i, key := range expiredKeys {
		delete(flm.locks, key)
		delete(flm.locksByID, expiredIDs[i])
	}

	if len(expiredKeys) > 0 {
		log.Debug().
			Int("expired_count", len(expiredKeys)).
			Msg("Cleaned up expired file locks")
	}
}

// TriggerCleanup manually triggers cleanup of expired locks
func (flm *FileLockManager) TriggerCleanup() {
	select {
	case flm.cleanup <- struct{}{}:
	default:
		// Channel is full, cleanup is already pending
	}
}

// Shutdown gracefully shuts down the lock manager
func (flm *FileLockManager) Shutdown() error {
	close(flm.done)

	// Release all locks
	flm.mu.Lock()
	lockCount := len(flm.locks)
	flm.locks = make(map[string]*FileLock)
	flm.locksByID = make(map[string]*FileLock)
	flm.mu.Unlock()

	log.Info().
		Int("released_locks", lockCount).
		Msg("File lock manager shut down")

	return nil
}

// GetStats returns statistics about the lock manager
func (flm *FileLockManager) GetStats() map[string]interface{} {
	flm.mu.RLock()
	defer flm.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_locks"] = len(flm.locks)
	stats["locks_by_type"] = make(map[string]int)

	readLocks := 0
	writeLocks := 0
	expiredLocks := 0
	now := time.Now()

	for _, lock := range flm.locks {
		if now.After(lock.ExpiresAt) {
			expiredLocks++
		} else {
			if lock.LockType == LockTypeRead {
				readLocks++
			} else {
				writeLocks++
			}
		}
	}

	stats["read_locks"] = readLocks
	stats["write_locks"] = writeLocks
	stats["expired_locks"] = expiredLocks

	return stats
}

// generateLockID generates a unique lock ID
func generateLockID(containerID, filePath string) string {
	return fmt.Sprintf("lock-%s-%s-%d", containerID[:8], generateRandomString(8), time.Now().UnixNano())
}

// WithLock executes a function while holding a file lock
func (flm *FileLockManager) WithLock(ctx context.Context, containerID, filePath string, lockType LockType, timeout time.Duration, fn func() error) error {
	lockID, err := flm.AcquireLockWithType(ctx, containerID, filePath, lockType, timeout)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}

	defer func() {
		if releaseErr := flm.ReleaseLock(containerID, filePath, lockID); releaseErr != nil {
			log.Warn().Err(releaseErr).Str("file_path", filePath).Msg("Failed to release lock")
		}
	}()

	return fn()
}

// LockGuard provides a convenient way to acquire and automatically release locks
type LockGuard struct {
	lockManager *FileLockManager
	containerID string
	filePath    string
	lockID      string
	released    bool
	mu          sync.Mutex
}

// NewLockGuard creates a new lock guard
func (flm *FileLockManager) NewLockGuard(ctx context.Context, containerID, filePath string, lockType LockType, timeout time.Duration) (*LockGuard, error) {
	lockID, err := flm.AcquireLockWithType(ctx, containerID, filePath, lockType, timeout)
	if err != nil {
		return nil, err
	}

	return &LockGuard{
		lockManager: flm,
		containerID: containerID,
		filePath:    filePath,
		lockID:      lockID,
		released:    false,
	}, nil
}

// Release releases the lock
func (lg *LockGuard) Release() error {
	lg.mu.Lock()
	defer lg.mu.Unlock()

	if lg.released {
		return errors.New("lock already released")
	}

	err := lg.lockManager.ReleaseLock(lg.containerID, lg.filePath, lg.lockID)
	if err == nil {
		lg.released = true
	}

	return err
}

// Extend extends the lock duration
func (lg *LockGuard) Extend(extension time.Duration) error {
	lg.mu.Lock()
	defer lg.mu.Unlock()

	if lg.released {
		return errors.New("cannot extend released lock")
	}

	return lg.lockManager.ExtendLock(lg.lockID, extension)
}

// IsReleased returns true if the lock has been released
func (lg *LockGuard) IsReleased() bool {
	lg.mu.Lock()
	defer lg.mu.Unlock()

	return lg.released
}