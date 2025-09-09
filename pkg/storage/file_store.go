package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
)

// FileMetadata represents metadata for a file
type FileMetadata struct {
	ID             int64                  `json:"id"`
	SandboxID      string                 `json:"sandbox_id"`
	FilePath       string                 `json:"file_path"`
	Checksum       string                 `json:"checksum"`
	SizeBytes      int64                  `json:"size_bytes"`
	MimeType       string                 `json:"mime_type"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	Version        int                    `json:"version"`
	ParentFileID   *int64                 `json:"parent_file_id,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	SearchContent  string                 `json:"search_content,omitempty"`
	AccessCount    int64                  `json:"access_count"`
	LastAccessed   *time.Time             `json:"last_accessed,omitempty"`
	DeletedAt      *time.Time             `json:"deleted_at,omitempty"`
}

// FileChunk represents a deduplicated file chunk
type FileChunk struct {
	ChunkHash string    `json:"chunk_hash"`
	Data      []byte    `json:"data"`
	SizeBytes int64     `json:"size_bytes"`
	RefCount  int64     `json:"ref_count"`
	CreatedAt time.Time `json:"created_at"`
}

// FileChunkRef represents a reference to a file chunk
type FileChunkRef struct {
	FileID     int64  `json:"file_id"`
	ChunkHash  string `json:"chunk_hash"`
	ChunkOrder int    `json:"chunk_order"`
}

// FileRelationship represents relationships between files
type FileRelationship struct {
	ParentID int64  `json:"parent_id"`
	ChildID  int64  `json:"child_id"`
	Type     string `json:"type"` // version, dependency, link, etc.
}

// SearchResult represents a file search result
type SearchResult struct {
	FileMetadata *FileMetadata `json:"file_metadata"`
	Rank         float64       `json:"rank"`
	Snippet      string        `json:"snippet"`
}

// FileFilter provides filtering options for file queries
type FileFilter struct {
	SandboxID      string
	FilePathPrefix string
	MimeType       string
	MinSize        int64
	MaxSize        int64
	CreatedAfter   time.Time
	CreatedBefore  time.Time
	AccessedAfter  time.Time
	AccessedBefore time.Time
	HasParent      *bool
	Limit          int
	Offset         int
}

// FileStore provides file metadata persistence and indexing
type FileStore struct {
	store          *SQLiteStore
	enableDedup    bool
	chunkSizeKB    int
	maxSearchResults int
}

// NewFileStore creates a new file store
func NewFileStore(store *SQLiteStore) *FileStore {
	return &FileStore{
		store:          store,
		enableDedup:    true,
		chunkSizeKB:    64, // 64KB chunks for deduplication
		maxSearchResults: 100,
	}
}

// Create stores new file metadata
func (f *FileStore) Create(ctx context.Context, metadata *FileMetadata) error {
	if metadata.SandboxID == "" || metadata.FilePath == "" {
		return fmt.Errorf("sandbox ID and file path cannot be empty")
	}

	// Generate checksum if not provided
	if metadata.Checksum == "" {
		metadata.Checksum = f.generateFilePathHash(metadata.SandboxID, metadata.FilePath)
	}

	// Detect MIME type if not provided
	if metadata.MimeType == "" {
		metadata.MimeType = mime.TypeByExtension(filepath.Ext(metadata.FilePath))
		if metadata.MimeType == "" {
			metadata.MimeType = "application/octet-stream"
		}
	}

	tx, err := f.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Serialize metadata JSON
	metadataJSON, err := json.Marshal(metadata.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Insert file metadata
	query := `
		INSERT INTO file_metadata (
			sandbox_id, file_path, checksum, size_bytes, mime_type,
			created_at, updated_at, version, parent_file_id, metadata,
			search_content, access_count, last_accessed
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := tx.Exec(query,
		metadata.SandboxID, metadata.FilePath, metadata.Checksum,
		metadata.SizeBytes, metadata.MimeType, metadata.CreatedAt,
		metadata.UpdatedAt, metadata.Version, metadata.ParentFileID,
		string(metadataJSON), metadata.SearchContent, metadata.AccessCount,
		metadata.LastAccessed)
	if err != nil {
		return fmt.Errorf("failed to insert file metadata: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get insert ID: %w", err)
	}

	metadata.ID = id

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info().
		Int64("file_id", metadata.ID).
		Str("sandbox_id", metadata.SandboxID).
		Str("file_path", metadata.FilePath).
		Msg("File metadata created successfully")

	return nil
}

// Get retrieves file metadata by ID
func (f *FileStore) Get(ctx context.Context, id int64) (*FileMetadata, error) {
	if id <= 0 {
		return nil, fmt.Errorf("file ID must be positive")
	}

	query := `
		SELECT id, sandbox_id, file_path, checksum, size_bytes, mime_type,
		       created_at, updated_at, version, parent_file_id, metadata,
		       search_content, access_count, last_accessed, deleted_at
		FROM file_metadata 
		WHERE id = ? AND deleted_at IS NULL`

	row := f.store.QueryRow(ctx, query, id)

	var metadata FileMetadata
	var metadataJSON string

	err := row.Scan(
		&metadata.ID, &metadata.SandboxID, &metadata.FilePath,
		&metadata.Checksum, &metadata.SizeBytes, &metadata.MimeType,
		&metadata.CreatedAt, &metadata.UpdatedAt, &metadata.Version,
		&metadata.ParentFileID, &metadataJSON, &metadata.SearchContent,
		&metadata.AccessCount, &metadata.LastAccessed, &metadata.DeletedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan file metadata: %w", err)
	}

	// Deserialize metadata JSON
	if metadataJSON != "" {
		if err := json.Unmarshal([]byte(metadataJSON), &metadata.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &metadata, nil
}

// GetByPath retrieves file metadata by sandbox ID and file path
func (f *FileStore) GetByPath(ctx context.Context, sandboxID, filePath string) (*FileMetadata, error) {
	if sandboxID == "" || filePath == "" {
		return nil, fmt.Errorf("sandbox ID and file path cannot be empty")
	}

	query := `
		SELECT id, sandbox_id, file_path, checksum, size_bytes, mime_type,
		       created_at, updated_at, version, parent_file_id, metadata,
		       search_content, access_count, last_accessed, deleted_at
		FROM file_metadata 
		WHERE sandbox_id = ? AND file_path = ? AND deleted_at IS NULL`

	row := f.store.QueryRow(ctx, query, sandboxID, filePath)

	var metadata FileMetadata
	var metadataJSON string

	err := row.Scan(
		&metadata.ID, &metadata.SandboxID, &metadata.FilePath,
		&metadata.Checksum, &metadata.SizeBytes, &metadata.MimeType,
		&metadata.CreatedAt, &metadata.UpdatedAt, &metadata.Version,
		&metadata.ParentFileID, &metadataJSON, &metadata.SearchContent,
		&metadata.AccessCount, &metadata.LastAccessed, &metadata.DeletedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan file metadata: %w", err)
	}

	// Deserialize metadata JSON
	if metadataJSON != "" {
		if err := json.Unmarshal([]byte(metadataJSON), &metadata.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &metadata, nil
}

// Update updates file metadata with optimistic locking
func (f *FileStore) Update(ctx context.Context, metadata *FileMetadata) error {
	if metadata.ID <= 0 {
		return fmt.Errorf("file ID must be positive")
	}

	tx, err := f.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get current version for optimistic locking
	currentRow := tx.QueryRow("SELECT version FROM file_metadata WHERE id = ?", metadata.ID)
	var currentVersion int
	if err := currentRow.Scan(&currentVersion); err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if metadata.Version != currentVersion {
		return fmt.Errorf("version mismatch: expected %d, got %d", currentVersion, metadata.Version)
	}

	// Increment version
	metadata.Version++
	metadata.UpdatedAt = time.Now()

	// Serialize metadata JSON
	metadataJSON, err := json.Marshal(metadata.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Update file metadata
	query := `
		UPDATE file_metadata 
		SET checksum = ?, size_bytes = ?, mime_type = ?, updated_at = ?,
		    version = ?, parent_file_id = ?, metadata = ?, search_content = ?
		WHERE id = ? AND version = ?`

	result, err := tx.Exec(query,
		metadata.Checksum, metadata.SizeBytes, metadata.MimeType,
		metadata.UpdatedAt, metadata.Version, metadata.ParentFileID,
		string(metadataJSON), metadata.SearchContent, metadata.ID, currentVersion)
	if err != nil {
		return fmt.Errorf("failed to update file metadata: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no rows updated, possible version conflict")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info().
		Int64("file_id", metadata.ID).
		Str("file_path", metadata.FilePath).
		Int("version", metadata.Version).
		Msg("File metadata updated successfully")

	return nil
}

// Delete performs soft delete of file metadata
func (f *FileStore) Delete(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("file ID must be positive")
	}

	query := "UPDATE file_metadata SET deleted_at = CURRENT_TIMESTAMP WHERE id = ? AND deleted_at IS NULL"
	result, err := f.store.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to soft delete file: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("file not found or already deleted")
	}

	log.Info().
		Int64("file_id", id).
		Msg("File metadata soft deleted successfully")

	return nil
}

// List retrieves file metadata with optional filtering
func (f *FileStore) List(ctx context.Context, filter *FileFilter) ([]*FileMetadata, error) {
	query := `
		SELECT id, sandbox_id, file_path, checksum, size_bytes, mime_type,
		       created_at, updated_at, version, parent_file_id, metadata,
		       search_content, access_count, last_accessed, deleted_at
		FROM file_metadata 
		WHERE deleted_at IS NULL`

	args := []interface{}{}

	if filter != nil {
		if filter.SandboxID != "" {
			query += " AND sandbox_id = ?"
			args = append(args, filter.SandboxID)
		}

		if filter.FilePathPrefix != "" {
			query += " AND file_path LIKE ?"
			args = append(args, filter.FilePathPrefix+"%")
		}

		if filter.MimeType != "" {
			query += " AND mime_type = ?"
			args = append(args, filter.MimeType)
		}

		if filter.MinSize > 0 {
			query += " AND size_bytes >= ?"
			args = append(args, filter.MinSize)
		}

		if filter.MaxSize > 0 {
			query += " AND size_bytes <= ?"
			args = append(args, filter.MaxSize)
		}

		if !filter.CreatedAfter.IsZero() {
			query += " AND created_at > ?"
			args = append(args, filter.CreatedAfter)
		}

		if !filter.CreatedBefore.IsZero() {
			query += " AND created_at < ?"
			args = append(args, filter.CreatedBefore)
		}

		if !filter.AccessedAfter.IsZero() {
			query += " AND last_accessed > ?"
			args = append(args, filter.AccessedAfter)
		}

		if !filter.AccessedBefore.IsZero() {
			query += " AND last_accessed < ?"
			args = append(args, filter.AccessedBefore)
		}

		if filter.HasParent != nil {
			if *filter.HasParent {
				query += " AND parent_file_id IS NOT NULL"
			} else {
				query += " AND parent_file_id IS NULL"
			}
		}

		query += " ORDER BY created_at DESC"

		if filter.Limit > 0 {
			query += " LIMIT ?"
			args = append(args, filter.Limit)

			if filter.Offset > 0 {
				query += " OFFSET ?"
				args = append(args, filter.Offset)
			}
		}
	} else {
		query += " ORDER BY created_at DESC"
	}

	rows, err := f.store.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query file metadata: %w", err)
	}
	defer rows.Close()

	var files []*FileMetadata
	for rows.Next() {
		var metadata FileMetadata
		var metadataJSON string

		err := rows.Scan(
			&metadata.ID, &metadata.SandboxID, &metadata.FilePath,
			&metadata.Checksum, &metadata.SizeBytes, &metadata.MimeType,
			&metadata.CreatedAt, &metadata.UpdatedAt, &metadata.Version,
			&metadata.ParentFileID, &metadataJSON, &metadata.SearchContent,
			&metadata.AccessCount, &metadata.LastAccessed, &metadata.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan file metadata: %w", err)
		}

		// Deserialize metadata JSON
		if metadataJSON != "" {
			if err := json.Unmarshal([]byte(metadataJSON), &metadata.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		files = append(files, &metadata)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return files, nil
}

// Search performs full-text search on file content and paths
func (f *FileStore) Search(ctx context.Context, sandboxID, query string, limit int) ([]*SearchResult, error) {
	if query == "" {
		return nil, fmt.Errorf("search query cannot be empty")
	}

	if limit <= 0 || limit > f.maxSearchResults {
		limit = f.maxSearchResults
	}

	// Try FTS5 search first, fall back to LIKE search if not available
	results, err := f.searchWithFTS(ctx, sandboxID, query, limit)
	if err != nil {
		// Fall back to LIKE-based search
		log.Warn().Err(err).Msg("FTS search failed, falling back to LIKE search")
		return f.searchWithLike(ctx, sandboxID, query, limit)
	}

	return results, nil
}

// searchWithFTS performs FTS5-based search
func (f *FileStore) searchWithFTS(ctx context.Context, sandboxID, query string, limit int) ([]*SearchResult, error) {
	// Use FTS5 for full-text search
	ftsQuery := `
		SELECT fm.id, fm.sandbox_id, fm.file_path, fm.checksum, fm.size_bytes, 
		       fm.mime_type, fm.created_at, fm.updated_at, fm.version, 
		       fm.parent_file_id, fm.metadata, fm.search_content, 
		       fm.access_count, fm.last_accessed, fm.deleted_at,
		       fts.rank, snippet(file_search_fts, 1, '<mark>', '</mark>', '...', 32) as snippet
		FROM file_search_fts fts
		JOIN file_metadata fm ON fm.id = fts.rowid
		WHERE file_search_fts MATCH ? AND fm.deleted_at IS NULL`

	args := []interface{}{query}

	if sandboxID != "" {
		ftsQuery += " AND fm.sandbox_id = ?"
		args = append(args, sandboxID)
	}

	ftsQuery += " ORDER BY fts.rank DESC LIMIT ?"
	args = append(args, limit)

	rows, err := f.store.Query(ctx, ftsQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*SearchResult
	for rows.Next() {
		var metadata FileMetadata
		var metadataJSON string
		var rank float64
		var snippet string

		err := rows.Scan(
			&metadata.ID, &metadata.SandboxID, &metadata.FilePath,
			&metadata.Checksum, &metadata.SizeBytes, &metadata.MimeType,
			&metadata.CreatedAt, &metadata.UpdatedAt, &metadata.Version,
			&metadata.ParentFileID, &metadataJSON, &metadata.SearchContent,
			&metadata.AccessCount, &metadata.LastAccessed, &metadata.DeletedAt,
			&rank, &snippet,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan FTS search result: %w", err)
		}

		// Deserialize metadata JSON
		if metadataJSON != "" {
			if err := json.Unmarshal([]byte(metadataJSON), &metadata.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		results = append(results, &SearchResult{
			FileMetadata: &metadata,
			Rank:         rank,
			Snippet:      snippet,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("FTS row iteration error: %w", err)
	}

	log.Info().
		Str("sandbox_id", sandboxID).
		Str("query", query).
		Int("results_count", len(results)).
		Str("search_type", "FTS").
		Msg("File search completed")

	return results, nil
}

// searchWithLike performs LIKE-based search as fallback
func (f *FileStore) searchWithLike(ctx context.Context, sandboxID, query string, limit int) ([]*SearchResult, error) {
	likeQuery := `
		SELECT id, sandbox_id, file_path, checksum, size_bytes, mime_type,
		       created_at, updated_at, version, parent_file_id, metadata,
		       search_content, access_count, last_accessed, deleted_at
		FROM file_metadata 
		WHERE (file_path LIKE ? OR search_content LIKE ?) 
			AND deleted_at IS NULL`

	args := []interface{}{
		"%" + query + "%",
		"%" + query + "%",
	}

	if sandboxID != "" {
		likeQuery += " AND sandbox_id = ?"
		args = append(args, sandboxID)
	}

	likeQuery += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := f.store.Query(ctx, likeQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute LIKE search: %w", err)
	}
	defer rows.Close()

	var results []*SearchResult
	for rows.Next() {
		var metadata FileMetadata
		var metadataJSON string

		err := rows.Scan(
			&metadata.ID, &metadata.SandboxID, &metadata.FilePath,
			&metadata.Checksum, &metadata.SizeBytes, &metadata.MimeType,
			&metadata.CreatedAt, &metadata.UpdatedAt, &metadata.Version,
			&metadata.ParentFileID, &metadataJSON, &metadata.SearchContent,
			&metadata.AccessCount, &metadata.LastAccessed, &metadata.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan LIKE search result: %w", err)
		}

		// Deserialize metadata JSON
		if metadataJSON != "" {
			if err := json.Unmarshal([]byte(metadataJSON), &metadata.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		results = append(results, &SearchResult{
			FileMetadata: &metadata,
			Rank:         1.0, // Simple ranking for LIKE search
			Snippet:      "", // No snippet for LIKE search
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("LIKE row iteration error: %w", err)
	}

	log.Info().
		Str("sandbox_id", sandboxID).
		Str("query", query).
		Int("results_count", len(results)).
		Str("search_type", "LIKE").
		Msg("File search completed")

	return results, nil
}

// RecordAccess updates file access count and timestamp
func (f *FileStore) RecordAccess(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("file ID must be positive")
	}

	query := `
		UPDATE file_metadata 
		SET access_count = access_count + 1, last_accessed = CURRENT_TIMESTAMP
		WHERE id = ? AND deleted_at IS NULL`

	result, err := f.store.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to record file access: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("file not found")
	}

	return nil
}

// CreateVersion creates a new version of a file
func (f *FileStore) CreateVersion(ctx context.Context, parentID int64, metadata *FileMetadata) error {
	if parentID <= 0 {
		return fmt.Errorf("parent file ID must be positive")
	}

	// Verify parent exists
	parent, err := f.Get(ctx, parentID)
	if err != nil {
		return fmt.Errorf("failed to get parent file: %w", err)
	}

	// Set parent relationship
	metadata.ParentFileID = &parentID
	metadata.SandboxID = parent.SandboxID
	metadata.Version = 1 // New version starts at 1

	if err := f.Create(ctx, metadata); err != nil {
		return fmt.Errorf("failed to create file version: %w", err)
	}

	log.Info().
		Int64("file_id", metadata.ID).
		Int64("parent_id", parentID).
		Str("file_path", metadata.FilePath).
		Msg("File version created successfully")

	return nil
}

// GetVersions retrieves all versions of a file
func (f *FileStore) GetVersions(ctx context.Context, parentID int64) ([]*FileMetadata, error) {
	if parentID <= 0 {
		return nil, fmt.Errorf("parent file ID must be positive")
	}

	// Get the parent file and all its versions
	query := `
		SELECT id, sandbox_id, file_path, checksum, size_bytes, mime_type,
		       created_at, updated_at, version, parent_file_id, metadata,
		       search_content, access_count, last_accessed, deleted_at
		FROM file_metadata 
		WHERE (id = ? OR parent_file_id = ?) AND deleted_at IS NULL
		ORDER BY created_at ASC`

	rows, err := f.store.Query(ctx, query, parentID, parentID)
	if err != nil {
		return nil, fmt.Errorf("failed to query file versions: %w", err)
	}
	defer rows.Close()

	var versions []*FileMetadata
	for rows.Next() {
		var metadata FileMetadata
		var metadataJSON string

		err := rows.Scan(
			&metadata.ID, &metadata.SandboxID, &metadata.FilePath,
			&metadata.Checksum, &metadata.SizeBytes, &metadata.MimeType,
			&metadata.CreatedAt, &metadata.UpdatedAt, &metadata.Version,
			&metadata.ParentFileID, &metadataJSON, &metadata.SearchContent,
			&metadata.AccessCount, &metadata.LastAccessed, &metadata.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan file version: %w", err)
		}

		// Deserialize metadata JSON
		if metadataJSON != "" {
			if err := json.Unmarshal([]byte(metadataJSON), &metadata.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		versions = append(versions, &metadata)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return versions, nil
}

// StoreChunk stores a deduplicated file chunk
func (f *FileStore) StoreChunk(ctx context.Context, data []byte) (string, error) {
	if !f.enableDedup {
		return "", fmt.Errorf("deduplication is disabled")
	}

	// Calculate hash for deduplication
	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])

	tx, err := f.store.BeginTransaction(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check if chunk already exists
	existsQuery := "SELECT chunk_hash FROM file_chunks WHERE chunk_hash = ?"
	existsRow := tx.QueryRow(existsQuery, hashStr)
	var existingHash string
	exists := existsRow.Scan(&existingHash) == nil

	if exists {
		// Increment reference count
		_, err := tx.Exec("UPDATE file_chunks SET ref_count = ref_count + 1 WHERE chunk_hash = ?", hashStr)
		if err != nil {
			return "", fmt.Errorf("failed to update chunk ref count: %w", err)
		}
	} else {
		// Store new chunk
		insertQuery := `
			INSERT INTO file_chunks (chunk_hash, data, size_bytes, ref_count, created_at)
			VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)`
		_, err := tx.Exec(insertQuery, hashStr, data, len(data))
		if err != nil {
			return "", fmt.Errorf("failed to insert chunk: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to commit transaction: %w", err)
	}

	return hashStr, nil
}

// RetrieveChunk retrieves a file chunk by hash
func (f *FileStore) RetrieveChunk(ctx context.Context, hash string) ([]byte, error) {
	if !f.enableDedup {
		return nil, fmt.Errorf("deduplication is disabled")
	}

	query := "SELECT data FROM file_chunks WHERE chunk_hash = ?"
	row := f.store.QueryRow(ctx, query, hash)

	var data []byte
	if err := row.Scan(&data); err != nil {
		return nil, fmt.Errorf("failed to retrieve chunk: %w", err)
	}

	return data, nil
}

// LinkChunks associates file chunks with a file
func (f *FileStore) LinkChunks(ctx context.Context, fileID int64, chunkHashes []string) error {
	if fileID <= 0 {
		return fmt.Errorf("file ID must be positive")
	}

	tx, err := f.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Remove existing chunk links
	_, err = tx.Exec("DELETE FROM file_chunk_refs WHERE file_id = ?", fileID)
	if err != nil {
		return fmt.Errorf("failed to remove existing chunk links: %w", err)
	}

	// Add new chunk links
	for i, chunkHash := range chunkHashes {
		insertQuery := "INSERT INTO file_chunk_refs (file_id, chunk_hash, chunk_order) VALUES (?, ?, ?)"
		_, err := tx.Exec(insertQuery, fileID, chunkHash, i)
		if err != nil {
			return fmt.Errorf("failed to link chunk %s: %w", chunkHash, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info().
		Int64("file_id", fileID).
		Int("chunk_count", len(chunkHashes)).
		Msg("File chunks linked successfully")

	return nil
}

// ReconstructFile reconstructs a file from its chunks
func (f *FileStore) ReconstructFile(ctx context.Context, fileID int64, writer io.Writer) error {
	if fileID <= 0 {
		return fmt.Errorf("file ID must be positive")
	}

	// Get ordered chunk hashes
	query := `
		SELECT chunk_hash 
		FROM file_chunk_refs 
		WHERE file_id = ? 
		ORDER BY chunk_order ASC`

	rows, err := f.store.Query(ctx, query, fileID)
	if err != nil {
		return fmt.Errorf("failed to query file chunks: %w", err)
	}
	defer rows.Close()

	var chunkHashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return fmt.Errorf("failed to scan chunk hash: %w", err)
		}
		chunkHashes = append(chunkHashes, hash)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("row iteration error: %w", err)
	}

	// Retrieve and write chunks in order
	for _, hash := range chunkHashes {
		data, err := f.RetrieveChunk(ctx, hash)
		if err != nil {
			return fmt.Errorf("failed to retrieve chunk %s: %w", hash, err)
		}

		if _, err := writer.Write(data); err != nil {
			return fmt.Errorf("failed to write chunk data: %w", err)
		}
	}

	return nil
}

// generateFilePathHash generates a hash for the file path combination
func (f *FileStore) generateFilePathHash(sandboxID, filePath string) string {
	hash := sha256.Sum256([]byte(sandboxID + ":" + filePath))
	return hex.EncodeToString(hash[:])
}

// OptimizeSearchIndex rebuilds the FTS index for better search performance
func (f *FileStore) OptimizeSearchIndex(ctx context.Context) error {
	query := "INSERT INTO file_search_fts(file_search_fts) VALUES('optimize')"
	_, err := f.store.Exec(ctx, query)
	if err != nil {
		log.Warn().Err(err).Msg("FTS optimization not available")
		return nil // Don't fail if FTS is not available
	}

	log.Info().Msg("File search index optimized successfully")
	return nil
}

// GetStorageStats returns storage statistics
func (f *FileStore) GetStorageStats(ctx context.Context, sandboxID string) (*StorageStats, error) {
	var stats StorageStats

	baseQuery := `
		SELECT 
			COUNT(*) as file_count,
			COALESCE(SUM(size_bytes), 0) as total_size,
			COALESCE(AVG(size_bytes), 0) as avg_size,
			COALESCE(MAX(size_bytes), 0) as max_size,
			COUNT(DISTINCT mime_type) as mime_type_count
		FROM file_metadata 
		WHERE deleted_at IS NULL`

	args := []interface{}{}
	if sandboxID != "" {
		baseQuery += " AND sandbox_id = ?"
		args = append(args, sandboxID)
	}

	row := f.store.QueryRow(ctx, baseQuery, args...)
	err := row.Scan(&stats.FileCount, &stats.TotalSize, &stats.AvgSize, &stats.MaxSize, &stats.MimeTypeCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get storage stats: %w", err)
	}

	// Get chunk deduplication stats if enabled
	if f.enableDedup {
		chunkQuery := `
			SELECT 
				COUNT(*) as chunk_count,
				COALESCE(SUM(size_bytes), 0) as total_chunk_size,
				COALESCE(SUM(ref_count), 0) as total_refs
			FROM file_chunks`

		chunkRow := f.store.QueryRow(ctx, chunkQuery)
		err := chunkRow.Scan(&stats.ChunkCount, &stats.TotalChunkSize, &stats.TotalChunkRefs)
		if err != nil {
			return nil, fmt.Errorf("failed to get chunk stats: %w", err)
		}

		if stats.TotalChunkRefs > 0 {
			stats.DeduplicationRatio = float64(stats.TotalChunkSize) / float64(stats.TotalSize)
		}
	}

	return &stats, nil
}

// StorageStats represents storage statistics
type StorageStats struct {
	FileCount          int64   `json:"file_count"`
	TotalSize          int64   `json:"total_size"`
	AvgSize            float64 `json:"avg_size"`
	MaxSize            int64   `json:"max_size"`
	MimeTypeCount      int64   `json:"mime_type_count"`
	ChunkCount         int64   `json:"chunk_count,omitempty"`
	TotalChunkSize     int64   `json:"total_chunk_size,omitempty"`
	TotalChunkRefs     int64   `json:"total_chunk_refs,omitempty"`
	DeduplicationRatio float64 `json:"deduplication_ratio,omitempty"`
}

// CleanupOrphanedChunks removes chunks that are no longer referenced
func (f *FileStore) CleanupOrphanedChunks(ctx context.Context) (int64, error) {
	if !f.enableDedup {
		return 0, nil
	}

	query := `
		DELETE FROM file_chunks 
		WHERE chunk_hash NOT IN (
			SELECT DISTINCT chunk_hash 
			FROM file_chunk_refs fcr
			JOIN file_metadata fm ON fcr.file_id = fm.id
			WHERE fm.deleted_at IS NULL
		)`

	result, err := f.store.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup orphaned chunks: %w", err)
	}

	deletedCount, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get deleted count: %w", err)
	}

	log.Info().
		Int64("deleted_chunks", deletedCount).
		Msg("Orphaned chunks cleaned up successfully")

	return deletedCount, nil
}