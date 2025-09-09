package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// SandboxState represents the complete state of a sandbox
type SandboxState struct {
	ID          string                 `json:"id"`
	ContainerID string                 `json:"container_id"`
	Status      string                 `json:"status"`
	WorkingDir  string                 `json:"working_dir"`
	Environment map[string]string      `json:"environment"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Config      map[string]interface{} `json:"config"`
	Metadata    map[string]interface{} `json:"metadata"`
	Version     int                    `json:"version"`
	DeletedAt   *time.Time             `json:"deleted_at,omitempty"`
	RecoveryData map[string]interface{} `json:"recovery_data,omitempty"`
}

// SandboxConfigVersion represents a versioned configuration
type SandboxConfigVersion struct {
	SandboxID   string                 `json:"sandbox_id"`
	Version     int                    `json:"version"`
	Config      map[string]interface{} `json:"config"`
	ChangedBy   string                 `json:"changed_by"`
	ChangedAt   time.Time              `json:"changed_at"`
	ChangeReason string                `json:"change_reason"`
	Checksum    string                 `json:"checksum"`
}

// AuditEntry represents an audit trail entry
type AuditEntry struct {
	ID         int64                  `json:"id"`
	EntityType string                 `json:"entity_type"`
	EntityID   string                 `json:"entity_id"`
	Action     string                 `json:"action"`
	OldData    map[string]interface{} `json:"old_data,omitempty"`
	NewData    map[string]interface{} `json:"new_data,omitempty"`
	UserID     string                 `json:"user_id,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// SandboxStore provides sandbox state persistence operations
type SandboxStore struct {
	store *SQLiteStore
}

// NewSandboxStore creates a new sandbox store
func NewSandboxStore(store *SQLiteStore) *SandboxStore {
	return &SandboxStore{
		store: store,
	}
}

// Create persists a new sandbox state
func (s *SandboxStore) Create(ctx context.Context, state *SandboxState) error {
	if state.ID == "" {
		return fmt.Errorf("sandbox ID cannot be empty")
	}

	tx, err := s.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Serialize JSON fields
	envJSON, err := json.Marshal(state.Environment)
	if err != nil {
		return fmt.Errorf("failed to marshal environment: %w", err)
	}

	configJSON, err := json.Marshal(state.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	metadataJSON, err := json.Marshal(state.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	recoveryJSON, err := json.Marshal(state.RecoveryData)
	if err != nil {
		return fmt.Errorf("failed to marshal recovery data: %w", err)
	}

	// Insert sandbox state
	query := `
		INSERT INTO sandboxes (
			id, container_id, status, working_dir, environment,
			created_at, updated_at, config, metadata, version, recovery_data
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = tx.Exec(query,
		state.ID, state.ContainerID, state.Status, state.WorkingDir,
		string(envJSON), state.CreatedAt, state.UpdatedAt,
		string(configJSON), string(metadataJSON), state.Version, string(recoveryJSON))
	if err != nil {
		return fmt.Errorf("failed to insert sandbox: %w", err)
	}

	// Create audit entry
	if err := s.createAuditEntry(tx, "sandbox", state.ID, "create", nil, state, "", nil); err != nil {
		log.Warn().Err(err).Msg("Failed to create audit entry")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info().
		Str("sandbox_id", state.ID).
		Str("status", state.Status).
		Msg("Sandbox state created successfully")

	return nil
}

// Get retrieves a sandbox state by ID
func (s *SandboxStore) Get(ctx context.Context, id string) (*SandboxState, error) {
	if id == "" {
		return nil, fmt.Errorf("sandbox ID cannot be empty")
	}

	query := `
		SELECT id, container_id, status, working_dir, environment,
		       created_at, updated_at, config, metadata, version,
		       deleted_at, recovery_data
		FROM sandboxes 
		WHERE id = ? AND deleted_at IS NULL`

	row := s.store.QueryRow(ctx, query, id)

	var state SandboxState
	var envJSON, configJSON, metadataJSON, recoveryJSON string
	var deletedAt *time.Time

	err := row.Scan(
		&state.ID, &state.ContainerID, &state.Status, &state.WorkingDir,
		&envJSON, &state.CreatedAt, &state.UpdatedAt,
		&configJSON, &metadataJSON, &state.Version,
		&deletedAt, &recoveryJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan sandbox: %w", err)
	}

	// Deserialize JSON fields
	if err := json.Unmarshal([]byte(envJSON), &state.Environment); err != nil {
		return nil, fmt.Errorf("failed to unmarshal environment: %w", err)
	}

	if err := json.Unmarshal([]byte(configJSON), &state.Config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := json.Unmarshal([]byte(metadataJSON), &state.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if recoveryJSON != "" {
		if err := json.Unmarshal([]byte(recoveryJSON), &state.RecoveryData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal recovery data: %w", err)
		}
	}

	state.DeletedAt = deletedAt

	return &state, nil
}

// Update updates an existing sandbox state with optimistic locking
func (s *SandboxStore) Update(ctx context.Context, state *SandboxState) error {
	if state.ID == "" {
		return fmt.Errorf("sandbox ID cannot be empty")
	}

	tx, err := s.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get current state for audit trail and version check
	oldState, err := s.Get(ctx, state.ID)
	if err != nil {
		return fmt.Errorf("failed to get current state: %w", err)
	}

	// Check version for optimistic locking
	if state.Version != oldState.Version {
		return fmt.Errorf("version mismatch: expected %d, got %d", oldState.Version, state.Version)
	}

	// Increment version
	state.Version++
	state.UpdatedAt = time.Now()

	// Serialize JSON fields
	envJSON, err := json.Marshal(state.Environment)
	if err != nil {
		return fmt.Errorf("failed to marshal environment: %w", err)
	}

	configJSON, err := json.Marshal(state.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	metadataJSON, err := json.Marshal(state.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	recoveryJSON, err := json.Marshal(state.RecoveryData)
	if err != nil {
		return fmt.Errorf("failed to marshal recovery data: %w", err)
	}

	// Update sandbox state
	query := `
		UPDATE sandboxes 
		SET container_id = ?, status = ?, working_dir = ?, environment = ?,
		    updated_at = ?, config = ?, metadata = ?, version = ?, recovery_data = ?
		WHERE id = ? AND version = ?`

	result, err := tx.Exec(query,
		state.ContainerID, state.Status, state.WorkingDir, string(envJSON),
		state.UpdatedAt, string(configJSON), string(metadataJSON), state.Version, string(recoveryJSON),
		state.ID, oldState.Version)
	if err != nil {
		return fmt.Errorf("failed to update sandbox: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no rows updated, possible version conflict")
	}

	// Create audit entry
	if err := s.createAuditEntry(tx, "sandbox", state.ID, "update", oldState, state, "", nil); err != nil {
		log.Warn().Err(err).Msg("Failed to create audit entry")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info().
		Str("sandbox_id", state.ID).
		Str("status", state.Status).
		Int("version", state.Version).
		Msg("Sandbox state updated successfully")

	return nil
}

// Delete performs soft delete of a sandbox
func (s *SandboxStore) Delete(ctx context.Context, id string, userID string) error {
	if id == "" {
		return fmt.Errorf("sandbox ID cannot be empty")
	}

	tx, err := s.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get current state for audit trail
	oldState, err := s.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get current state: %w", err)
	}

	// Soft delete
	query := "UPDATE sandboxes SET deleted_at = CURRENT_TIMESTAMP WHERE id = ? AND deleted_at IS NULL"
	result, err := tx.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to soft delete sandbox: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("sandbox not found or already deleted")
	}

	// Create audit entry
	if err := s.createAuditEntry(tx, "sandbox", id, "delete", oldState, nil, userID, nil); err != nil {
		log.Warn().Err(err).Msg("Failed to create audit entry")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info().
		Str("sandbox_id", id).
		Str("user_id", userID).
		Msg("Sandbox soft deleted successfully")

	return nil
}

// List retrieves all active sandboxes with optional filtering
func (s *SandboxStore) List(ctx context.Context, filter *SandboxFilter) ([]*SandboxState, error) {
	query := `
		SELECT id, container_id, status, working_dir, environment,
		       created_at, updated_at, config, metadata, version,
		       deleted_at, recovery_data
		FROM sandboxes 
		WHERE deleted_at IS NULL`

	args := []interface{}{}
	argIndex := 1

	if filter != nil {
		if filter.Status != "" {
			query += " AND status = ?"
			args = append(args, filter.Status)
			argIndex++
		}

		if !filter.CreatedAfter.IsZero() {
			query += " AND created_at > ?"
			args = append(args, filter.CreatedAfter)
			argIndex++
		}

		if !filter.CreatedBefore.IsZero() {
			query += " AND created_at < ?"
			args = append(args, filter.CreatedBefore)
			argIndex++
		}

		if filter.Limit > 0 {
			query += " LIMIT ?"
			args = append(args, filter.Limit)
		}
	}

	query += " ORDER BY created_at DESC"

	rows, err := s.store.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query sandboxes: %w", err)
	}
	defer rows.Close()

	var states []*SandboxState
	for rows.Next() {
		var state SandboxState
		var envJSON, configJSON, metadataJSON, recoveryJSON string
		var deletedAt *time.Time

		err := rows.Scan(
			&state.ID, &state.ContainerID, &state.Status, &state.WorkingDir,
			&envJSON, &state.CreatedAt, &state.UpdatedAt,
			&configJSON, &metadataJSON, &state.Version,
			&deletedAt, &recoveryJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan sandbox: %w", err)
		}

		// Deserialize JSON fields
		if err := json.Unmarshal([]byte(envJSON), &state.Environment); err != nil {
			return nil, fmt.Errorf("failed to unmarshal environment: %w", err)
		}

		if err := json.Unmarshal([]byte(configJSON), &state.Config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config: %w", err)
		}

		if err := json.Unmarshal([]byte(metadataJSON), &state.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		if recoveryJSON != "" {
			if err := json.Unmarshal([]byte(recoveryJSON), &state.RecoveryData); err != nil {
				return nil, fmt.Errorf("failed to unmarshal recovery data: %w", err)
			}
		}

		state.DeletedAt = deletedAt
		states = append(states, &state)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return states, nil
}

// SandboxFilter provides filtering options for sandbox queries
type SandboxFilter struct {
	Status        string
	CreatedAfter  time.Time
	CreatedBefore time.Time
	Limit         int
}

// Recover restores a soft-deleted sandbox
func (s *SandboxStore) Recover(ctx context.Context, id string, userID string) error {
	if id == "" {
		return fmt.Errorf("sandbox ID cannot be empty")
	}

	tx, err := s.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check if sandbox exists and is deleted
	query := "SELECT id FROM sandboxes WHERE id = ? AND deleted_at IS NOT NULL"
	row := tx.QueryRow(query, id)
	var checkID string
	if err := row.Scan(&checkID); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return fmt.Errorf("sandbox not found or not deleted")
		}
		return fmt.Errorf("failed to check sandbox: %w", err)
	}

	// Recover sandbox
	query = "UPDATE sandboxes SET deleted_at = NULL WHERE id = ?"
	result, err := tx.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to recover sandbox: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no rows updated")
	}

	// Create audit entry
	metadata := map[string]interface{}{
		"action": "recover",
	}
	if err := s.createAuditEntry(tx, "sandbox", id, "recover", nil, nil, userID, metadata); err != nil {
		log.Warn().Err(err).Msg("Failed to create audit entry")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info().
		Str("sandbox_id", id).
		Str("user_id", userID).
		Msg("Sandbox recovered successfully")

	return nil
}

// CreateCheckpoint creates a state checkpoint for recovery
func (s *SandboxStore) CreateCheckpoint(ctx context.Context, id string, reason string, checkpointData map[string]interface{}) error {
	if id == "" {
		return fmt.Errorf("sandbox ID cannot be empty")
	}

	tx, err := s.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get current state
	state, err := s.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get sandbox state: %w", err)
	}

	// Update recovery data
	if state.RecoveryData == nil {
		state.RecoveryData = make(map[string]interface{})
	}

	state.RecoveryData["checkpoint_reason"] = reason
	state.RecoveryData["checkpoint_time"] = time.Now()
	state.RecoveryData["checkpoint_data"] = checkpointData

	// Update sandbox with new recovery data
	recoveryJSON, err := json.Marshal(state.RecoveryData)
	if err != nil {
		return fmt.Errorf("failed to marshal recovery data: %w", err)
	}

	query := "UPDATE sandboxes SET recovery_data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
	_, err = tx.Exec(query, string(recoveryJSON), id)
	if err != nil {
		return fmt.Errorf("failed to update recovery data: %w", err)
	}

	// Create audit entry
	metadata := map[string]interface{}{
		"action": "checkpoint",
		"reason": reason,
	}
	if err := s.createAuditEntry(tx, "sandbox", id, "checkpoint", nil, checkpointData, "", metadata); err != nil {
		log.Warn().Err(err).Msg("Failed to create audit entry")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info().
		Str("sandbox_id", id).
		Str("reason", reason).
		Msg("Checkpoint created successfully")

	return nil
}

// GetAuditTrail retrieves audit trail for a sandbox
func (s *SandboxStore) GetAuditTrail(ctx context.Context, entityID string, limit int) ([]*AuditEntry, error) {
	if entityID == "" {
		return nil, fmt.Errorf("entity ID cannot be empty")
	}

	query := `
		SELECT id, entity_type, entity_id, action, old_data, new_data,
		       user_id, timestamp, metadata
		FROM audit_trail 
		WHERE entity_id = ?
		ORDER BY timestamp DESC`

	args := []interface{}{entityID}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.store.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit trail: %w", err)
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		var entry AuditEntry
		var oldDataJSON, newDataJSON, metadataJSON string
		var userID *string

		err := rows.Scan(
			&entry.ID, &entry.EntityType, &entry.EntityID, &entry.Action,
			&oldDataJSON, &newDataJSON, &userID, &entry.Timestamp, &metadataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit entry: %w", err)
		}

		if userID != nil {
			entry.UserID = *userID
		}

		// Deserialize JSON fields
		if oldDataJSON != "" {
			if err := json.Unmarshal([]byte(oldDataJSON), &entry.OldData); err != nil {
				return nil, fmt.Errorf("failed to unmarshal old data: %w", err)
			}
		}

		if newDataJSON != "" {
			if err := json.Unmarshal([]byte(newDataJSON), &entry.NewData); err != nil {
				return nil, fmt.Errorf("failed to unmarshal new data: %w", err)
			}
		}

		if metadataJSON != "" {
			if err := json.Unmarshal([]byte(metadataJSON), &entry.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		entries = append(entries, &entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return entries, nil
}

// createAuditEntry creates an audit trail entry
func (s *SandboxStore) createAuditEntry(
	tx *Transaction,
	entityType, entityID, action string,
	oldData, newData interface{},
	userID string,
	metadata map[string]interface{},
) error {
	var oldDataJSON, newDataJSON, metadataJSON string
	var err error

	if oldData != nil {
		oldDataBytes, err := json.Marshal(oldData)
		if err != nil {
			return fmt.Errorf("failed to marshal old data: %w", err)
		}
		oldDataJSON = string(oldDataBytes)
	}

	if newData != nil {
		newDataBytes, err := json.Marshal(newData)
		if err != nil {
			return fmt.Errorf("failed to marshal new data: %w", err)
		}
		newDataJSON = string(newDataBytes)
	}

	if metadata != nil {
		metadataBytes, err := json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		metadataJSON = string(metadataBytes)
	}

	query := `
		INSERT INTO audit_trail (
			entity_type, entity_id, action, old_data, new_data,
			user_id, timestamp, metadata
		) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)`

	var userIDPtr *string
	if userID != "" {
		userIDPtr = &userID
	}

	_, err = tx.Exec(query, entityType, entityID, action, oldDataJSON, newDataJSON, userIDPtr, metadataJSON)
	if err != nil {
		return fmt.Errorf("failed to insert audit entry: %w", err)
	}

	return nil
}

// CleanupDeleted permanently removes soft-deleted sandboxes older than the retention period
func (s *SandboxStore) CleanupDeleted(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, fmt.Errorf("retention days must be positive")
	}

	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)
	
	tx, err := s.store.BeginTransaction(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get sandboxes to be permanently deleted for audit
	query := `SELECT id FROM sandboxes WHERE deleted_at IS NOT NULL AND deleted_at < ?`
	rows, err := tx.Query(query, cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("failed to query deleted sandboxes: %w", err)
	}

	var sandboxIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("failed to scan sandbox ID: %w", err)
		}
		sandboxIDs = append(sandboxIDs, id)
	}
	rows.Close()

	if len(sandboxIDs) == 0 {
		return 0, nil
	}

	// Permanently delete sandboxes
	query = `DELETE FROM sandboxes WHERE deleted_at IS NOT NULL AND deleted_at < ?`
	result, err := tx.Exec(query, cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("failed to delete sandboxes: %w", err)
	}

	deletedCount, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get deleted count: %w", err)
	}

	// Create audit entries for permanent deletions
	for _, id := range sandboxIDs {
		metadata := map[string]interface{}{
			"action": "permanent_delete",
			"retention_days": retentionDays,
		}
		if err := s.createAuditEntry(tx, "sandbox", id, "permanent_delete", nil, nil, "system", metadata); err != nil {
			log.Warn().Err(err).Str("sandbox_id", id).Msg("Failed to create permanent delete audit entry")
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info().
		Int64("deleted_count", deletedCount).
		Int("retention_days", retentionDays).
		Msg("Permanently deleted expired sandboxes")

	return deletedCount, nil
}