package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewSQLiteCommandCache(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := CacheConfig{
		DatabasePath:     filepath.Join(tempDir, "test_cache.db"),
		MaxEntries:       100,
		DefaultTTL:       1 * time.Hour,
		CleanupInterval:  30 * time.Minute,
		CompressionLevel: 6,
		CompressionMin:   1024,
		EnableWarming:    false, // Disable for tests
		WarmCommands:     []string{},
		MaxCacheSize:     10 * 1024 * 1024, // 10MB
	}

	cache, err := NewSQLiteCommandCache(config)
	if err != nil {
		t.Fatalf("NewSQLiteCommandCache() error: %v", err)
	}
	defer cache.Close()

	if cache == nil {
		t.Fatal("NewSQLiteCommandCache() returned nil")
	}

	// Test that database was created
	if _, err := os.Stat(config.DatabasePath); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}
}

func TestCommandCache_StoreAndGet(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := DefaultCacheConfig()
	config.DatabasePath = filepath.Join(tempDir, "test_cache.db")
	config.EnableWarming = false

	cache, err := NewSQLiteCommandCache(config)
	if err != nil {
		t.Fatalf("NewSQLiteCommandCache() error: %v", err)
	}
	defer cache.Close()

	// Create test entry
	entry := &CommandCacheEntry{
		SandboxID:     "test-sandbox",
		Command:       "echo hello",
		Args:          []string{"echo", "hello"},
		WorkingDir:    "/workspace",
		Environment:   map[string]string{"TEST": "value"},
		ExitCode:      0,
		Stdout:        "hello\n",
		Stderr:        "",
		ExecutionTime: 100 * time.Millisecond,
		Timestamp:     time.Now(),
		Metadata:      map[string]interface{}{"test": "metadata"},
		FileHashes:    map[string]string{"/test/file": "hash123"},
	}

	// Store entry
	err = cache.Store(entry)
	if err != nil {
		t.Errorf("Store() error: %v", err)
	}

	// Get entry
	retrieved, err := cache.Get(entry.CacheKey)
	if err != nil {
		t.Errorf("Get() error: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Get() returned nil")
	}

	// Verify entry data
	if retrieved.SandboxID != entry.SandboxID {
		t.Errorf("SandboxID mismatch: expected %s, got %s", entry.SandboxID, retrieved.SandboxID)
	}
	if retrieved.Command != entry.Command {
		t.Errorf("Command mismatch: expected %s, got %s", entry.Command, retrieved.Command)
	}
	if retrieved.ExitCode != entry.ExitCode {
		t.Errorf("ExitCode mismatch: expected %d, got %d", entry.ExitCode, retrieved.ExitCode)
	}
	if retrieved.Stdout != entry.Stdout {
		t.Errorf("Stdout mismatch: expected %s, got %s", entry.Stdout, retrieved.Stdout)
	}
	if retrieved.HitCount != 0 {
		t.Errorf("Expected HitCount 0 for first retrieval, got %d", retrieved.HitCount)
	}

	// Get same entry again (should increment hit count)
	retrieved2, err := cache.Get(entry.CacheKey)
	if err != nil {
		t.Errorf("Second Get() error: %v", err)
	}
	if retrieved2.HitCount != 1 {
		t.Errorf("Expected HitCount 1 for second retrieval, got %d", retrieved2.HitCount)
	}
}

func TestCommandCache_Expiration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := DefaultCacheConfig()
	config.DatabasePath = filepath.Join(tempDir, "test_cache.db")
	config.DefaultTTL = 100 * time.Millisecond // Very short TTL
	config.EnableWarming = false

	cache, err := NewSQLiteCommandCache(config)
	if err != nil {
		t.Fatalf("NewSQLiteCommandCache() error: %v", err)
	}
	defer cache.Close()

	// Create and store entry
	entry := &CommandCacheEntry{
		SandboxID:     "test-sandbox",
		Command:       "echo expired",
		Args:          []string{"echo", "expired"},
		WorkingDir:    "/workspace",
		ExitCode:      0,
		Stdout:        "expired\n",
		ExecutionTime: 50 * time.Millisecond,
		Timestamp:     time.Now(),
	}

	err = cache.Store(entry)
	if err != nil {
		t.Errorf("Store() error: %v", err)
	}

	// Immediately retrieve (should work)
	retrieved, err := cache.Get(entry.CacheKey)
	if err != nil {
		t.Errorf("Get() error: %v", err)
	}
	if retrieved == nil {
		t.Error("Entry should be available immediately after storage")
	}

	// Wait for expiration
	time.Sleep(200 * time.Millisecond)

	// Try to retrieve expired entry
	expired, err := cache.Get(entry.CacheKey)
	if err != nil {
		t.Errorf("Get() error after expiration: %v", err)
	}
	if expired != nil {
		t.Error("Entry should be nil after expiration")
	}
}

func TestCommandCache_GetHistory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := DefaultCacheConfig()
	config.DatabasePath = filepath.Join(tempDir, "test_cache.db")
	config.EnableWarming = false

	cache, err := NewSQLiteCommandCache(config)
	if err != nil {
		t.Fatalf("NewSQLiteCommandCache() error: %v", err)
	}
	defer cache.Close()

	// Store multiple entries
	entries := []*CommandCacheEntry{
		{
			SandboxID:     "sandbox-1",
			Command:       "ls -la",
			Args:          []string{"ls", "-la"},
			ExitCode:      0,
			ExecutionTime: 50 * time.Millisecond,
			Timestamp:     time.Now().Add(-3 * time.Hour),
		},
		{
			SandboxID:     "sandbox-1",
			Command:       "pwd",
			Args:          []string{"pwd"},
			ExitCode:      0,
			ExecutionTime: 25 * time.Millisecond,
			Timestamp:     time.Now().Add(-2 * time.Hour),
		},
		{
			SandboxID:     "sandbox-2",
			Command:       "echo test",
			Args:          []string{"echo", "test"},
			ExitCode:      0,
			ExecutionTime: 75 * time.Millisecond,
			Timestamp:     time.Now().Add(-30 * time.Minute),
		},
	}

	for _, entry := range entries {
		err = cache.Store(entry)
		if err != nil {
			t.Errorf("Store() error: %v", err)
		}
	}

	tests := []struct {
		name     string
		filter   CommandHistoryFilter
		expected int
	}{
		{
			name:     "all entries",
			filter:   CommandHistoryFilter{},
			expected: 3,
		},
		{
			name: "filter by sandbox",
			filter: CommandHistoryFilter{
				SandboxID: "sandbox-1",
			},
			expected: 2,
		},
		{
			name: "filter by command",
			filter: CommandHistoryFilter{
				Command: "echo",
			},
			expected: 1,
		},
		{
			name: "filter by time range",
			filter: CommandHistoryFilter{
				StartTime: time.Now().Add(-90 * time.Minute),
				EndTime:   time.Now(),
			},
			expected: 1,
		},
		{
			name: "with limit",
			filter: CommandHistoryFilter{
				Limit: 2,
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			history, err := cache.GetHistory(tt.filter)
			if err != nil {
				t.Errorf("GetHistory() error: %v", err)
				return
			}

			if len(history) != tt.expected {
				t.Errorf("Expected %d entries, got %d", tt.expected, len(history))
			}
		})
	}
}

func TestCommandCache_InvalidateByPattern(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := DefaultCacheConfig()
	config.DatabasePath = filepath.Join(tempDir, "test_cache.db")
	config.EnableWarming = false

	cache, err := NewSQLiteCommandCache(config)
	if err != nil {
		t.Fatalf("NewSQLiteCommandCache() error: %v", err)
	}
	defer cache.Close()

	// Store entries with different command patterns
	commands := []string{"ls -la", "ls -l", "pwd", "echo test"}
	for _, cmd := range commands {
		entry := &CommandCacheEntry{
			Command:       cmd,
			Args:          []string{cmd},
			ExitCode:      0,
			ExecutionTime: 50 * time.Millisecond,
			Timestamp:     time.Now(),
		}
		err = cache.Store(entry)
		if err != nil {
			t.Errorf("Store() error: %v", err)
		}
	}

	// Invalidate entries matching pattern
	err = cache.InvalidateByPattern("ls%")
	if err != nil {
		t.Errorf("InvalidateByPattern() error: %v", err)
	}

	// Check that ls commands were invalidated
	history, err := cache.GetHistory(CommandHistoryFilter{})
	if err != nil {
		t.Errorf("GetHistory() error: %v", err)
	}

	for _, entry := range history {
		if strings.HasPrefix(entry.Command, "ls") {
			t.Errorf("Entry with command '%s' should have been invalidated", entry.Command)
		}
	}

	// Check that other commands remain
	foundPwd := false
	foundEcho := false
	for _, entry := range history {
		if entry.Command == "pwd" {
			foundPwd = true
		}
		if entry.Command == "echo test" {
			foundEcho = true
		}
	}

	if !foundPwd {
		t.Error("pwd command should not have been invalidated")
	}
	if !foundEcho {
		t.Error("echo command should not have been invalidated")
	}
}

func TestCommandCache_Statistics(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := DefaultCacheConfig()
	config.DatabasePath = filepath.Join(tempDir, "test_cache.db")
	config.EnableWarming = false

	cache, err := NewSQLiteCommandCache(config)
	if err != nil {
		t.Fatalf("NewSQLiteCommandCache() error: %v", err)
	}
	defer cache.Close()

	// Store some entries and collect their cache keys
	var storedEntries []*CommandCacheEntry
	for i := 0; i < 5; i++ {
		entry := &CommandCacheEntry{
			Command:       fmt.Sprintf("command-%d", i),
			Args:          []string{fmt.Sprintf("command-%d", i)},
			ExitCode:      i % 2, // Mix success and failure
			ExecutionTime: time.Duration(i*10) * time.Millisecond,
			Timestamp:     time.Now().Add(-time.Duration(i) * time.Hour),
			Stdout:        fmt.Sprintf("output-%d", i),
			Stderr:        "",
			WorkingDir:    "/workspace",
		}
		err = cache.Store(entry)
		if err != nil {
			t.Errorf("Store() error: %v", err)
		}
		storedEntries = append(storedEntries, entry)
	}

	// Access some entries to generate hits
	if len(storedEntries) > 0 {
		for i := 0; i < 3; i++ {
			// Simulate cache hits by getting the first stored entry
			if retrieved, _ := cache.Get(storedEntries[0].CacheKey); retrieved != nil {
				// Hit registered
			}
		}
	}

	stats, err := cache.GetStatistics()
	if err != nil {
		t.Errorf("GetStatistics() error: %v", err)
	}

	if stats.TotalEntries != 5 {
		t.Errorf("Expected 5 total entries, got %d", stats.TotalEntries)
	}

	if stats.TotalSize == 0 {
		t.Error("Expected total size > 0")
	}

	if len(stats.MostUsedCommands) == 0 {
		t.Error("Expected some most used commands")
	}

	if stats.OldestEntry.IsZero() {
		t.Error("Oldest entry timestamp should be set")
	}

	if stats.NewestEntry.IsZero() {
		t.Error("Newest entry timestamp should be set")
	}
}

func TestCommandCache_Cleanup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := DefaultCacheConfig()
	config.DatabasePath = filepath.Join(tempDir, "test_cache.db")
	config.DefaultTTL = 100 * time.Millisecond // Very short TTL
	config.EnableWarming = false

	cache, err := NewSQLiteCommandCache(config)
	if err != nil {
		t.Fatalf("NewSQLiteCommandCache() error: %v", err)
	}
	defer cache.Close()

	// Store some entries
	for i := 0; i < 5; i++ {
		entry := &CommandCacheEntry{
			Command:       fmt.Sprintf("command-%d", i),
			Args:          []string{fmt.Sprintf("command-%d", i)},
			ExitCode:      0,
			ExecutionTime: 50 * time.Millisecond,
			Timestamp:     time.Now(),
		}
		err = cache.Store(entry)
		if err != nil {
			t.Errorf("Store() error: %v", err)
		}
	}

	// Verify entries are stored
	stats, _ := cache.GetStatistics()
	if stats.TotalEntries != 5 {
		t.Errorf("Expected 5 entries before cleanup, got %d", stats.TotalEntries)
	}

	// Wait for expiration
	time.Sleep(200 * time.Millisecond)

	// Run cleanup
	err = cache.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() error: %v", err)
	}

	// Verify expired entries were removed
	stats, _ = cache.GetStatistics()
	if stats.TotalEntries > 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", stats.TotalEntries)
	}
}

func TestCommandCache_SizeLimits(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := DefaultCacheConfig()
	config.DatabasePath = filepath.Join(tempDir, "test_cache.db")
	config.MaxEntries = 3      // Very small limit
	config.MaxCacheSize = 1024 // 1KB limit
	config.EnableWarming = false

	cache, err := NewSQLiteCommandCache(config)
	if err != nil {
		t.Fatalf("NewSQLiteCommandCache() error: %v", err)
	}
	defer cache.Close()

	// Store entries that exceed limits
	largeOutput := strings.Repeat("Large output line\n", 100)
	for i := 0; i < 10; i++ {
		entry := &CommandCacheEntry{
			Command:       fmt.Sprintf("command-%d", i),
			Args:          []string{fmt.Sprintf("command-%d", i)},
			ExitCode:      0,
			Stdout:        largeOutput,
			ExecutionTime: 50 * time.Millisecond,
			Timestamp:     time.Now(),
		}
		err = cache.Store(entry)
		if err != nil {
			t.Errorf("Store() error: %v", err)
		}
	}

	// Force cleanup to apply limits
	err = cache.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() error: %v", err)
	}

	// Check that limits were enforced
	stats, _ := cache.GetStatistics()
	if stats.TotalEntries > config.MaxEntries {
		t.Errorf("Entry limit not enforced: expected <= %d, got %d", config.MaxEntries, stats.TotalEntries)
	}
}

func TestCacheConfig_Default(t *testing.T) {
	config := DefaultCacheConfig()

	if config.DatabasePath == "" {
		t.Error("Default database path should not be empty")
	}
	if config.MaxEntries <= 0 {
		t.Error("Default max entries should be > 0")
	}
	if config.DefaultTTL <= 0 {
		t.Error("Default TTL should be > 0")
	}
	if config.CleanupInterval <= 0 {
		t.Error("Default cleanup interval should be > 0")
	}
	if config.MaxCacheSize <= 0 {
		t.Error("Default max cache size should be > 0")
	}
	if len(config.WarmCommands) == 0 {
		t.Error("Default warm commands should not be empty")
	}
}

func TestCommandCacheEntry_Validation(t *testing.T) {
	entry := &CommandCacheEntry{
		SandboxID:     "test-sandbox",
		Command:       "echo test",
		Args:          []string{"echo", "test"},
		WorkingDir:    "/workspace",
		Environment:   map[string]string{},
		ExitCode:      0,
		Stdout:        "test\n",
		Stderr:        "",
		ExecutionTime: 100 * time.Millisecond,
		Timestamp:     time.Now(),
		Metadata:      map[string]interface{}{},
		FileHashes:    map[string]string{},
	}

	// Test required fields
	if entry.SandboxID == "" {
		t.Error("SandboxID should not be empty")
	}
	if entry.Command == "" {
		t.Error("Command should not be empty")
	}
	if len(entry.Args) == 0 {
		t.Error("Args should not be empty")
	}
	if entry.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}

	// Test that entry can be serialized to JSON
	_, err := json.Marshal(entry)
	if err != nil {
		t.Errorf("CommandCacheEntry should be JSON serializable: %v", err)
	}
}

// Benchmark tests
func BenchmarkCommandCache_Store(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "cache_bench")
	if err != nil {
		b.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := DefaultCacheConfig()
	config.DatabasePath = filepath.Join(tempDir, "bench_cache.db")
	config.EnableWarming = false

	cache, err := NewSQLiteCommandCache(config)
	if err != nil {
		b.Fatalf("NewSQLiteCommandCache() error: %v", err)
	}
	defer cache.Close()

	entry := &CommandCacheEntry{
		SandboxID:     "bench-sandbox",
		Command:       "echo benchmark",
		Args:          []string{"echo", "benchmark"},
		WorkingDir:    "/workspace",
		ExitCode:      0,
		Stdout:        "benchmark output\n",
		ExecutionTime: 100 * time.Millisecond,
		Timestamp:     time.Now(),
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		entry.Command = fmt.Sprintf("echo benchmark %d", i)
		entry.CacheKey = "" // Reset to generate new key
		cache.Store(entry)
	}
}

func BenchmarkCommandCache_Get(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "cache_bench")
	if err != nil {
		b.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := DefaultCacheConfig()
	config.DatabasePath = filepath.Join(tempDir, "bench_cache.db")
	config.EnableWarming = false

	cache, err := NewSQLiteCommandCache(config)
	if err != nil {
		b.Fatalf("NewSQLiteCommandCache() error: %v", err)
	}
	defer cache.Close()

	// Pre-populate cache
	entries := make([]*CommandCacheEntry, 100)
	for i := 0; i < 100; i++ {
		entry := &CommandCacheEntry{
			Command:       fmt.Sprintf("echo benchmark %d", i),
			Args:          []string{"echo", "benchmark", fmt.Sprintf("%d", i)},
			ExitCode:      0,
			ExecutionTime: 50 * time.Millisecond,
			Timestamp:     time.Now(),
		}
		cache.Store(entry)
		entries[i] = entry
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		entry := entries[i%len(entries)]
		cache.Get(entry.CacheKey)
	}
}
