package tools

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

// CommandCache manages command history and caching with SQLite storage
type CommandCache interface {
	// Store stores a command execution result in the cache
	Store(entry *CommandCacheEntry) error

	// Get retrieves a cached command result
	Get(key string) (*CommandCacheEntry, error)

	// GetHistory returns command history with optional filters
	GetHistory(filter CommandHistoryFilter) ([]*CommandCacheEntry, error)

	// InvalidateByPattern invalidates cache entries matching a pattern
	InvalidateByPattern(pattern string) error

	// InvalidateByFileChange invalidates cache based on file changes
	InvalidateByFileChange(filePath string, modTime time.Time) error

	// GetStatistics returns cache statistics and hit rates
	GetStatistics() (*CacheStatistics, error)

	// WarmCache pre-warms the cache with common commands
	WarmCache(commands []string, sandboxID string) error

	// Cleanup removes expired entries and manages cache size
	Cleanup() error

	// Close closes the cache and cleans up resources
	Close() error
}

// CommandCacheEntry represents a cached command execution result
type CommandCacheEntry struct {
	ID            int64                  `json:"id"`
	CacheKey      string                 `json:"cache_key"`
	SandboxID     string                 `json:"sandbox_id"`
	Command       string                 `json:"command"`
	Args          []string               `json:"args"`
	WorkingDir    string                 `json:"working_dir"`
	Environment   map[string]string      `json:"environment"`
	ExitCode      int                    `json:"exit_code"`
	Stdout        string                 `json:"stdout"`
	Stderr        string                 `json:"stderr"`
	ExecutionTime time.Duration          `json:"execution_time"`
	Timestamp     time.Time              `json:"timestamp"`
	ExpiresAt     time.Time              `json:"expires_at"`
	HitCount      int64                  `json:"hit_count"`
	LastAccessed  time.Time              `json:"last_accessed"`
	Metadata      map[string]interface{} `json:"metadata"`
	FileHashes    map[string]string      `json:"file_hashes"`
	Compressed    bool                   `json:"compressed"`
	Size          int64                  `json:"size"`
}

// CommandHistoryFilter provides filtering options for command history
type CommandHistoryFilter struct {
	SandboxID     string    `json:"sandbox_id"`
	Command       string    `json:"command"`
	ExitCode      *int      `json:"exit_code"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	Limit         int       `json:"limit"`
	Offset        int       `json:"offset"`
	OrderBy       string    `json:"order_by"` // "timestamp", "execution_time", "hit_count"
	OrderDesc     bool      `json:"order_desc"`
	IncludeOutput bool      `json:"include_output"`
}

// CacheStatistics provides cache performance metrics
type CacheStatistics struct {
	TotalEntries     int64               `json:"total_entries"`
	TotalHits        int64               `json:"total_hits"`
	TotalMisses      int64               `json:"total_misses"`
	HitRate          float64             `json:"hit_rate"`
	TotalSize        int64               `json:"total_size"`
	AverageHitCount  float64             `json:"average_hit_count"`
	ExpiredEntries   int64               `json:"expired_entries"`
	MostUsedCommands []CommandUsageStats `json:"most_used_commands"`
	SizeByType       map[string]int64    `json:"size_by_type"`
	OldestEntry      time.Time           `json:"oldest_entry"`
	NewestEntry      time.Time           `json:"newest_entry"`
}

// CommandUsageStats tracks usage statistics for commands
type CommandUsageStats struct {
	Command     string        `json:"command"`
	UsageCount  int64         `json:"usage_count"`
	TotalTime   time.Duration `json:"total_time"`
	AverageTime time.Duration `json:"average_time"`
	SuccessRate float64       `json:"success_rate"`
	LastUsed    time.Time     `json:"last_used"`
}

// CacheConfig provides configuration for the command cache
type CacheConfig struct {
	DatabasePath     string        `json:"database_path"`
	MaxEntries       int64         `json:"max_entries"`
	DefaultTTL       time.Duration `json:"default_ttl"`
	CleanupInterval  time.Duration `json:"cleanup_interval"`
	CompressionLevel int           `json:"compression_level"`
	CompressionMin   int64         `json:"compression_min"`
	EnableWarming    bool          `json:"enable_warming"`
	WarmCommands     []string      `json:"warm_commands"`
	MaxCacheSize     int64         `json:"max_cache_size"` // in bytes
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		DatabasePath:     "/tmp/sandboxrunner/command_cache.db",
		MaxEntries:       10000,
		DefaultTTL:       24 * time.Hour,
		CleanupInterval:  1 * time.Hour,
		CompressionLevel: 6,
		CompressionMin:   1024, // Compress if > 1KB
		EnableWarming:    true,
		WarmCommands: []string{
			"ls -la", "pwd", "whoami", "date", "ps aux",
			"df -h", "free -m", "uptime", "env", "uname -a",
		},
		MaxCacheSize: 100 * 1024 * 1024, // 100MB
	}
}

// SQLiteCommandCache implements CommandCache using SQLite
type SQLiteCommandCache struct {
	config   CacheConfig
	db       *sql.DB
	mutex    sync.RWMutex
	stats    CacheStatistics
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewSQLiteCommandCache creates a new SQLite-based command cache
func NewSQLiteCommandCache(config CacheConfig) (*SQLiteCommandCache, error) {
	// Create database directory if it doesn't exist
	dbDir := filepath.Dir(config.DatabasePath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open database connection
	db, err := sql.Open("sqlite3", config.DatabasePath+"?_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	cache := &SQLiteCommandCache{
		config:   config,
		db:       db,
		stopChan: make(chan struct{}),
		stats:    CacheStatistics{},
	}

	// Initialize database schema
	if err := cache.initializeSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Start cleanup worker
	cache.wg.Add(1)
	go cache.cleanupWorker()

	// Warm cache if enabled
	if config.EnableWarming {
		go cache.warmCacheAsync()
	}

	return cache, nil
}

// initializeSchema creates the necessary database tables
func (c *SQLiteCommandCache) initializeSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS command_cache (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cache_key TEXT NOT NULL UNIQUE,
		sandbox_id TEXT NOT NULL,
		command TEXT NOT NULL,
		args TEXT, -- JSON array
		working_dir TEXT,
		environment TEXT, -- JSON object
		exit_code INTEGER NOT NULL,
		stdout BLOB,
		stderr BLOB,
		execution_time INTEGER, -- nanoseconds
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		hit_count INTEGER DEFAULT 0,
		last_accessed DATETIME DEFAULT CURRENT_TIMESTAMP,
		metadata TEXT, -- JSON object
		file_hashes TEXT, -- JSON object
		compressed INTEGER DEFAULT 0,
		size INTEGER DEFAULT 0
	);
	
	CREATE INDEX IF NOT EXISTS idx_cache_key ON command_cache (cache_key);
	CREATE INDEX IF NOT EXISTS idx_sandbox_id ON command_cache (sandbox_id);
	CREATE INDEX IF NOT EXISTS idx_command ON command_cache (command);
	CREATE INDEX IF NOT EXISTS idx_expires_at ON command_cache (expires_at);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON command_cache (timestamp);
	CREATE INDEX IF NOT EXISTS idx_last_accessed ON command_cache (last_accessed);
	
	CREATE TABLE IF NOT EXISTS cache_statistics (
		id INTEGER PRIMARY KEY,
		total_hits INTEGER DEFAULT 0,
		total_misses INTEGER DEFAULT 0,
		last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	-- Initialize statistics if not exists
	INSERT OR IGNORE INTO cache_statistics (id, total_hits, total_misses) VALUES (1, 0, 0);
	`

	_, err := c.db.Exec(schema)
	return err
}

// Store stores a command execution result in the cache
func (c *SQLiteCommandCache) Store(entry *CommandCacheEntry) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Generate cache key if not provided
	if entry.CacheKey == "" {
		entry.CacheKey = c.generateCacheKey(entry.Command, entry.Args, entry.Environment, entry.WorkingDir)
	}

	// Set expiration time if not provided
	if entry.ExpiresAt.IsZero() {
		entry.ExpiresAt = time.Now().Add(c.config.DefaultTTL)
	}

	// Compress output if configured
	stdout, stderr := entry.Stdout, entry.Stderr
	if c.shouldCompress(entry) {
		compressedStdout, err := c.compressData([]byte(entry.Stdout))
		if err == nil {
			stdout = string(compressedStdout)
			entry.Compressed = true
		}

		compressedStderr, err := c.compressData([]byte(entry.Stderr))
		if err == nil {
			stderr = string(compressedStderr)
		}
	}

	// Convert to JSON
	argsJSON, _ := json.Marshal(entry.Args)
	envJSON, _ := json.Marshal(entry.Environment)
	metadataJSON, _ := json.Marshal(entry.Metadata)
	fileHashesJSON, _ := json.Marshal(entry.FileHashes)

	// Calculate size
	entry.Size = int64(len(stdout) + len(stderr) + len(string(argsJSON)) + len(string(envJSON)))

	query := `
	INSERT OR REPLACE INTO command_cache (
		cache_key, sandbox_id, command, args, working_dir, environment,
		exit_code, stdout, stderr, execution_time, timestamp, expires_at,
		hit_count, last_accessed, metadata, file_hashes, compressed, size
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
	`

	result, err := c.db.Exec(query,
		entry.CacheKey, entry.SandboxID, entry.Command, string(argsJSON), entry.WorkingDir,
		string(envJSON), entry.ExitCode, stdout, stderr, int64(entry.ExecutionTime),
		entry.Timestamp, entry.ExpiresAt, entry.Timestamp, string(metadataJSON),
		string(fileHashesJSON), entry.Compressed, entry.Size,
	)

	if err != nil {
		return fmt.Errorf("failed to store cache entry: %w", err)
	}

	if id, err := result.LastInsertId(); err == nil {
		entry.ID = id
	}

	log.Debug().
		Str("cache_key", entry.CacheKey).
		Str("command", entry.Command).
		Int64("size", entry.Size).
		Bool("compressed", entry.Compressed).
		Msg("Stored command in cache")

	return nil
}

// Get retrieves a cached command result
func (c *SQLiteCommandCache) Get(key string) (*CommandCacheEntry, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	query := `
	SELECT id, cache_key, sandbox_id, command, args, working_dir, environment,
		   exit_code, stdout, stderr, execution_time, timestamp, expires_at,
		   hit_count, last_accessed, metadata, file_hashes, compressed, size
	FROM command_cache 
	WHERE cache_key = ? AND expires_at > ?
	`

	row := c.db.QueryRow(query, key, time.Now())

	entry := &CommandCacheEntry{}
	var argsJSON, envJSON, metadataJSON, fileHashesJSON string
	var executionTimeNs int64

	err := row.Scan(
		&entry.ID, &entry.CacheKey, &entry.SandboxID, &entry.Command,
		&argsJSON, &entry.WorkingDir, &envJSON, &entry.ExitCode,
		&entry.Stdout, &entry.Stderr, &executionTimeNs, &entry.Timestamp,
		&entry.ExpiresAt, &entry.HitCount, &entry.LastAccessed,
		&metadataJSON, &fileHashesJSON, &entry.Compressed, &entry.Size,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			c.updateCacheStats(false) // Cache miss
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get cache entry: %w", err)
	}

	// Parse JSON fields
	json.Unmarshal([]byte(argsJSON), &entry.Args)
	json.Unmarshal([]byte(envJSON), &entry.Environment)
	json.Unmarshal([]byte(metadataJSON), &entry.Metadata)
	json.Unmarshal([]byte(fileHashesJSON), &entry.FileHashes)

	entry.ExecutionTime = time.Duration(executionTimeNs)

	// Decompress output if needed
	if entry.Compressed {
		if decompressed, err := c.decompressData([]byte(entry.Stdout)); err == nil {
			entry.Stdout = string(decompressed)
		}
		if decompressed, err := c.decompressData([]byte(entry.Stderr)); err == nil {
			entry.Stderr = string(decompressed)
		}
	}

	// Update hit count and last accessed
	c.updateHitCount(entry.ID)
	c.updateCacheStats(true) // Cache hit

	log.Debug().
		Str("cache_key", entry.CacheKey).
		Str("command", entry.Command).
		Int64("hit_count", entry.HitCount+1).
		Msg("Cache hit for command")

	return entry, nil
}

// GetHistory returns command history with optional filters
func (c *SQLiteCommandCache) GetHistory(filter CommandHistoryFilter) ([]*CommandCacheEntry, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	query := c.buildHistoryQuery(filter)
	args := c.buildHistoryArgs(filter)

	rows, err := c.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query history: %w", err)
	}
	defer rows.Close()

	var entries []*CommandCacheEntry
	for rows.Next() {
		entry := &CommandCacheEntry{}
		var argsJSON, envJSON, metadataJSON, fileHashesJSON string
		var executionTimeNs int64
		var stdout, stderr interface{} // Can be nil if not included

		scanArgs := []interface{}{
			&entry.ID, &entry.CacheKey, &entry.SandboxID, &entry.Command,
			&argsJSON, &entry.WorkingDir, &envJSON, &entry.ExitCode,
			&executionTimeNs, &entry.Timestamp, &entry.ExpiresAt,
			&entry.HitCount, &entry.LastAccessed, &metadataJSON,
			&fileHashesJSON, &entry.Compressed, &entry.Size,
		}

		if filter.IncludeOutput {
			scanArgs = append(scanArgs, &stdout, &stderr)
		}

		if err := rows.Scan(scanArgs...); err != nil {
			return nil, fmt.Errorf("failed to scan history row: %w", err)
		}

		// Parse JSON fields
		json.Unmarshal([]byte(argsJSON), &entry.Args)
		json.Unmarshal([]byte(envJSON), &entry.Environment)
		json.Unmarshal([]byte(metadataJSON), &entry.Metadata)
		json.Unmarshal([]byte(fileHashesJSON), &entry.FileHashes)

		entry.ExecutionTime = time.Duration(executionTimeNs)

		// Handle output if included
		if filter.IncludeOutput {
			if stdout != nil {
				entry.Stdout = string(stdout.([]byte))
			}
			if stderr != nil {
				entry.Stderr = string(stderr.([]byte))
			}

			// Decompress if needed
			if entry.Compressed {
				if decompressed, err := c.decompressData([]byte(entry.Stdout)); err == nil {
					entry.Stdout = string(decompressed)
				}
				if decompressed, err := c.decompressData([]byte(entry.Stderr)); err == nil {
					entry.Stderr = string(decompressed)
				}
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// InvalidateByPattern invalidates cache entries matching a pattern
func (c *SQLiteCommandCache) InvalidateByPattern(pattern string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	query := `DELETE FROM command_cache WHERE command LIKE ?`
	result, err := c.db.Exec(query, pattern)
	if err != nil {
		return fmt.Errorf("failed to invalidate by pattern: %w", err)
	}

	if affected, err := result.RowsAffected(); err == nil {
		log.Info().
			Str("pattern", pattern).
			Int64("affected", affected).
			Msg("Invalidated cache entries by pattern")
	}

	return nil
}

// InvalidateByFileChange invalidates cache based on file changes
func (c *SQLiteCommandCache) InvalidateByFileChange(filePath string, modTime time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Find entries that depend on this file
	query := `
	SELECT id, file_hashes FROM command_cache 
	WHERE file_hashes LIKE ? AND expires_at > ?
	`

	rows, err := c.db.Query(query, "%"+filePath+"%", time.Now())
	if err != nil {
		return fmt.Errorf("failed to query file dependencies: %w", err)
	}
	defer rows.Close()

	var idsToInvalidate []int64
	for rows.Next() {
		var id int64
		var fileHashesJSON string
		if err := rows.Scan(&id, &fileHashesJSON); err != nil {
			continue
		}

		var fileHashes map[string]string
		if json.Unmarshal([]byte(fileHashesJSON), &fileHashes) == nil {
			if hash, exists := fileHashes[filePath]; exists {
				// Check if file has actually changed
				if currentHash, err := c.calculateFileHash(filePath); err == nil {
					if currentHash != hash {
						idsToInvalidate = append(idsToInvalidate, id)
					}
				}
			}
		}
	}

	// Invalidate affected entries
	if len(idsToInvalidate) > 0 {
		placeholders := strings.Repeat("?,", len(idsToInvalidate))
		placeholders = placeholders[:len(placeholders)-1] // Remove trailing comma

		deleteQuery := fmt.Sprintf("DELETE FROM command_cache WHERE id IN (%s)", placeholders)
		args := make([]interface{}, len(idsToInvalidate))
		for i, id := range idsToInvalidate {
			args[i] = id
		}

		if _, err := c.db.Exec(deleteQuery, args...); err != nil {
			return fmt.Errorf("failed to invalidate by file change: %w", err)
		}

		log.Info().
			Str("file", filePath).
			Int("invalidated", len(idsToInvalidate)).
			Msg("Invalidated cache entries due to file change")
	}

	return nil
}

// GetStatistics returns cache statistics and hit rates
func (c *SQLiteCommandCache) GetStatistics() (*CacheStatistics, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	stats := &CacheStatistics{}

	// Get basic counts
	var totalHitsDB, totalSizeDB sql.NullInt64
	var avgHitCountDB sql.NullFloat64
	var oldestEntryStr, newestEntryStr sql.NullString

	err := c.db.QueryRow(`
		SELECT 
			COUNT(*) as total_entries,
			COALESCE(SUM(hit_count), 0) as total_hits,
			COALESCE(SUM(size), 0) as total_size,
			COALESCE(AVG(hit_count), 0) as avg_hit_count,
			COUNT(CASE WHEN expires_at < ? THEN 1 END) as expired_entries,
			MIN(timestamp) as oldest_entry,
			MAX(timestamp) as newest_entry
		FROM command_cache
	`, time.Now()).Scan(
		&stats.TotalEntries, &totalHitsDB, &totalSizeDB,
		&avgHitCountDB, &stats.ExpiredEntries,
		&oldestEntryStr, &newestEntryStr,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get basic statistics: %w", err)
	}

	// Handle nullable values
	if totalHitsDB.Valid {
		stats.TotalHits = totalHitsDB.Int64
	}
	if totalSizeDB.Valid {
		stats.TotalSize = totalSizeDB.Int64
	}
	if avgHitCountDB.Valid {
		stats.AverageHitCount = avgHitCountDB.Float64
	}

	// Parse timestamp strings with multiple formats
	if oldestEntryStr.Valid {
		timestampFormats := []string{
			"2006-01-02 15:04:05.999999999-07:00", // SQLite format with nanoseconds and timezone
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05Z",
			"2006-01-02T15:04:05.000Z",
		}
		
		for _, format := range timestampFormats {
			if parsed, parseErr := time.Parse(format, oldestEntryStr.String); parseErr == nil {
				stats.OldestEntry = parsed
				break
			}
		}
	}
	if newestEntryStr.Valid {
		timestampFormats := []string{
			"2006-01-02 15:04:05.999999999-07:00", // SQLite format with nanoseconds and timezone
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05Z",
			"2006-01-02T15:04:05.000Z",
		}
		
		for _, format := range timestampFormats {
			if parsed, parseErr := time.Parse(format, newestEntryStr.String); parseErr == nil {
				stats.NewestEntry = parsed
				break
			}
		}
	}

	// Get total misses from statistics table
	c.db.QueryRow("SELECT total_hits, total_misses FROM cache_statistics WHERE id = 1").
		Scan(&stats.TotalHits, &stats.TotalMisses)

	// Calculate hit rate
	if stats.TotalHits+stats.TotalMisses > 0 {
		stats.HitRate = float64(stats.TotalHits) / float64(stats.TotalHits+stats.TotalMisses)
	}

	// Get most used commands
	stats.MostUsedCommands = c.getMostUsedCommands(10)

	// Get size by type (compressed vs uncompressed)
	stats.SizeByType = make(map[string]int64)
	rows, err := c.db.Query(`
		SELECT compressed, SUM(size) FROM command_cache 
		WHERE expires_at > ? 
		GROUP BY compressed
	`, time.Now())

	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var compressed bool
			var size int64
			if rows.Scan(&compressed, &size) == nil {
				if compressed {
					stats.SizeByType["compressed"] = size
				} else {
					stats.SizeByType["uncompressed"] = size
				}
			}
		}
	}

	return stats, nil
}

// WarmCache pre-warms the cache with common commands
func (c *SQLiteCommandCache) WarmCache(commands []string, sandboxID string) error {
	if len(commands) == 0 {
		commands = c.config.WarmCommands
	}

	log.Info().
		Int("commands", len(commands)).
		Str("sandbox_id", sandboxID).
		Msg("Starting cache warming")

	// This is a placeholder - in a real implementation, you would
	// execute these commands and store the results
	for _, cmd := range commands {
		cacheKey := c.generateCacheKey(cmd, nil, nil, "/workspace")

		// Check if already cached
		if entry, _ := c.Get(cacheKey); entry != nil {
			continue // Already cached
		}

		// Create a placeholder entry for warming
		entry := &CommandCacheEntry{
			CacheKey:      cacheKey,
			SandboxID:     sandboxID,
			Command:       cmd,
			WorkingDir:    "/workspace",
			ExitCode:      0,
			Stdout:        "", // Would be filled by actual execution
			Stderr:        "",
			ExecutionTime: 0,
			Timestamp:     time.Now(),
			Metadata:      map[string]interface{}{"warmed": true},
		}

		if err := c.Store(entry); err != nil {
			log.Warn().Err(err).Str("command", cmd).Msg("Failed to warm cache entry")
		}
	}

	return nil
}

// Cleanup removes expired entries and manages cache size
func (c *SQLiteCommandCache) Cleanup() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	log.Debug().Msg("Starting cache cleanup")

	// Remove expired entries
	expiredResult, err := c.db.Exec("DELETE FROM command_cache WHERE expires_at < ?", time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired entries: %w", err)
	}

	expiredCount, _ := expiredResult.RowsAffected()

	// Check if we need to enforce size limits
	if c.config.MaxEntries > 0 || c.config.MaxCacheSize > 0 {
		if err := c.enforceLimits(); err != nil {
			return fmt.Errorf("failed to enforce limits: %w", err)
		}
	}

	// Vacuum database periodically
	if _, err := c.db.Exec("VACUUM"); err != nil {
		log.Warn().Err(err).Msg("Failed to vacuum database")
	}

	log.Info().
		Int64("expired_removed", expiredCount).
		Msg("Cache cleanup completed")

	return nil
}

// Close closes the cache and cleans up resources
func (c *SQLiteCommandCache) Close() error {
	close(c.stopChan)
	c.wg.Wait()

	if c.db != nil {
		return c.db.Close()
	}

	return nil
}

// Helper methods

// generateCacheKey generates a unique cache key for a command
func (c *SQLiteCommandCache) generateCacheKey(command string, args []string, env map[string]string, workingDir string) string {
	hasher := sha256.New()

	// Include command
	hasher.Write([]byte(command))

	// Include sorted args
	if len(args) > 0 {
		sort.Strings(args)
		hasher.Write([]byte(strings.Join(args, "\x00")))
	}

	// Include sorted environment variables
	if len(env) > 0 {
		var envPairs []string
		for k, v := range env {
			envPairs = append(envPairs, k+"="+v)
		}
		sort.Strings(envPairs)
		hasher.Write([]byte(strings.Join(envPairs, "\x00")))
	}

	// Include working directory
	hasher.Write([]byte(workingDir))

	return hex.EncodeToString(hasher.Sum(nil))
}

// shouldCompress determines if an entry should be compressed
func (c *SQLiteCommandCache) shouldCompress(entry *CommandCacheEntry) bool {
	if c.config.CompressionLevel == 0 {
		return false
	}

	totalSize := int64(len(entry.Stdout) + len(entry.Stderr))
	return totalSize >= c.config.CompressionMin
}

// compressData compresses data using gzip
func (c *SQLiteCommandCache) compressData(data []byte) ([]byte, error) {
	// Placeholder for gzip compression
	// In a real implementation, you would use compress/gzip
	return data, nil
}

// decompressData decompresses gzip data
func (c *SQLiteCommandCache) decompressData(data []byte) ([]byte, error) {
	// Placeholder for gzip decompression
	// In a real implementation, you would use compress/gzip
	return data, nil
}

// calculateFileHash calculates SHA256 hash of a file
func (c *SQLiteCommandCache) calculateFileHash(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// updateHitCount updates the hit count for a cache entry
func (c *SQLiteCommandCache) updateHitCount(id int64) {
	_, err := c.db.Exec(`
		UPDATE command_cache 
		SET hit_count = hit_count + 1, last_accessed = ? 
		WHERE id = ?
	`, time.Now(), id)

	if err != nil {
		log.Warn().Err(err).Int64("id", id).Msg("Failed to update hit count")
	}
}

// updateCacheStats updates global cache statistics
func (c *SQLiteCommandCache) updateCacheStats(hit bool) {
	field := "total_misses"
	if hit {
		field = "total_hits"
	}

	query := fmt.Sprintf(`
		UPDATE cache_statistics 
		SET %s = %s + 1, last_updated = ? 
		WHERE id = 1
	`, field, field)

	_, err := c.db.Exec(query, time.Now())
	if err != nil {
		log.Warn().Err(err).Bool("hit", hit).Msg("Failed to update cache statistics")
	}
}

// buildHistoryQuery builds the SQL query for history filtering
func (c *SQLiteCommandCache) buildHistoryQuery(filter CommandHistoryFilter) string {
	query := `SELECT id, cache_key, sandbox_id, command, args, working_dir, environment,
		exit_code, execution_time, timestamp, expires_at, hit_count, last_accessed,
		metadata, file_hashes, compressed, size`

	if filter.IncludeOutput {
		query += `, stdout, stderr`
	}

	query += ` FROM command_cache WHERE 1=1`

	if filter.SandboxID != "" {
		query += ` AND sandbox_id = ?`
	}

	if filter.Command != "" {
		query += ` AND command LIKE ?`
	}

	if filter.ExitCode != nil {
		query += ` AND exit_code = ?`
	}

	if !filter.StartTime.IsZero() {
		query += ` AND timestamp >= ?`
	}

	if !filter.EndTime.IsZero() {
		query += ` AND timestamp <= ?`
	}

	// Add ordering
	orderBy := "timestamp"
	if filter.OrderBy != "" {
		orderBy = filter.OrderBy
	}

	query += fmt.Sprintf(` ORDER BY %s`, orderBy)
	if filter.OrderDesc {
		query += ` DESC`
	}

	// Add limits
	if filter.Limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, filter.Limit)
		if filter.Offset > 0 {
			query += fmt.Sprintf(` OFFSET %d`, filter.Offset)
		}
	}

	return query
}

// buildHistoryArgs builds the arguments for history query
func (c *SQLiteCommandCache) buildHistoryArgs(filter CommandHistoryFilter) []interface{} {
	var args []interface{}

	if filter.SandboxID != "" {
		args = append(args, filter.SandboxID)
	}

	if filter.Command != "" {
		args = append(args, "%"+filter.Command+"%")
	}

	if filter.ExitCode != nil {
		args = append(args, *filter.ExitCode)
	}

	if !filter.StartTime.IsZero() {
		args = append(args, filter.StartTime)
	}

	if !filter.EndTime.IsZero() {
		args = append(args, filter.EndTime)
	}

	return args
}

// getMostUsedCommands gets the most frequently used commands
func (c *SQLiteCommandCache) getMostUsedCommands(limit int) []CommandUsageStats {
	query := `
	SELECT command, MAX(hit_count) as usage_count, 
		   SUM(execution_time) as total_time, 
		   AVG(execution_time) as avg_time,
		   AVG(CASE WHEN exit_code = 0 THEN 1.0 ELSE 0.0 END) as success_rate,
		   MAX(timestamp) as last_used
	FROM command_cache 
	WHERE expires_at > ?
	GROUP BY command 
	ORDER BY usage_count DESC 
	LIMIT ?
	`

	rows, err := c.db.Query(query, time.Now(), limit)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get most used commands")
		return nil
	}
	defer rows.Close()

	var stats []CommandUsageStats
	for rows.Next() {
		var stat CommandUsageStats
		var totalTimeNs int64
		var avgTimeNs float64
		var lastUsedStr string

		if err := rows.Scan(&stat.Command, &stat.UsageCount, &totalTimeNs,
			&avgTimeNs, &stat.SuccessRate, &lastUsedStr); err != nil {
			continue
		}
		
		// Parse the timestamp string
		timestampFormats := []string{
			"2006-01-02 15:04:05.999999999-07:00", // SQLite format with nanoseconds and timezone
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02 15:04:05",
		}
		
		for _, format := range timestampFormats {
			if parsed, parseErr := time.Parse(format, lastUsedStr); parseErr == nil {
				stat.LastUsed = parsed
				break
			}
		}

		stat.TotalTime = time.Duration(totalTimeNs)
		stat.AverageTime = time.Duration(int64(avgTimeNs))
		stats = append(stats, stat)
	}

	return stats
}

// enforceLimits enforces cache size and entry limits using LRU eviction
func (c *SQLiteCommandCache) enforceLimits() error {
	// Check entry count limit
	if c.config.MaxEntries > 0 {
		var count int64
		c.db.QueryRow("SELECT COUNT(*) FROM command_cache").Scan(&count)

		if count > c.config.MaxEntries {
			excess := count - c.config.MaxEntries
			// Remove least recently accessed entries
			_, err := c.db.Exec(`
				DELETE FROM command_cache 
				WHERE id IN (
					SELECT id FROM command_cache 
					ORDER BY last_accessed ASC 
					LIMIT ?
				)
			`, excess)

			if err != nil {
				return fmt.Errorf("failed to enforce entry limit: %w", err)
			}
		}
	}

	// Check size limit
	if c.config.MaxCacheSize > 0 {
		var totalSize int64
		c.db.QueryRow("SELECT SUM(size) FROM command_cache").Scan(&totalSize)

		if totalSize > c.config.MaxCacheSize {
			// Remove entries until under limit, starting with least recently accessed
			query := `
			DELETE FROM command_cache 
			WHERE id IN (
				SELECT id FROM command_cache 
				ORDER BY last_accessed ASC 
				LIMIT 1
			)
			`

			// Keep removing until under limit (with safety counter)
			for i := 0; i < 1000 && totalSize > c.config.MaxCacheSize; i++ {
				result, err := c.db.Exec(query)
				if err != nil || result == nil {
					break
				}

				affected, _ := result.RowsAffected()
				if affected == 0 {
					break
				}

				// Recalculate size
				c.db.QueryRow("SELECT COALESCE(SUM(size), 0) FROM command_cache").Scan(&totalSize)
			}
		}
	}

	return nil
}

// cleanupWorker runs periodic cleanup
func (c *SQLiteCommandCache) cleanupWorker() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			if err := c.Cleanup(); err != nil {
				log.Error().Err(err).Msg("Cache cleanup failed")
			}
		}
	}
}

// warmCacheAsync warms the cache asynchronously
func (c *SQLiteCommandCache) warmCacheAsync() {
	time.Sleep(5 * time.Second) // Wait a bit before warming

	if err := c.WarmCache(c.config.WarmCommands, "system"); err != nil {
		log.Warn().Err(err).Msg("Failed to warm cache")
	}
}
