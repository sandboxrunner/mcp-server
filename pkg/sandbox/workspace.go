package sandbox

import (
	"context"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/sandboxrunner/mcp-server/pkg/runtime"
)

// WorkspaceManager manages sandbox workspaces with advanced features
type WorkspaceManager struct {
	containerFS     runtime.ContainerFS
	workspaces      map[string]*Workspace
	templates       map[string]*ProjectTemplate
	snapshots       map[string]*WorkspaceSnapshot
	mu              sync.RWMutex
	cleanupScheduler *CleanupScheduler
	sharingManager  *WorkspaceShareManager
}

// Workspace represents a managed workspace with metadata and capabilities
type Workspace struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	SandboxID     string                 `json:"sandbox_id"`
	ContainerID   string                 `json:"container_id"`
	RootPath      string                 `json:"root_path"`
	Type          WorkspaceType          `json:"type"`
	Template      string                 `json:"template,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	LastAccessed  time.Time              `json:"last_accessed"`
	Size          int64                  `json:"size_bytes"`
	FileCount     int64                  `json:"file_count"`
	MaxSize       int64                  `json:"max_size_bytes"`
	MaxFiles      int64                  `json:"max_files"`
	Structure     *WorkspaceStructure    `json:"structure"`
	Metadata      map[string]interface{} `json:"metadata"`
	Tags          []string               `json:"tags"`
	Owner         string                 `json:"owner,omitempty"`
	Permissions   WorkspacePermissions   `json:"permissions"`
	Status        WorkspaceStatus        `json:"status"`
	SharedWith    []string               `json:"shared_with,omitempty"`
}

// WorkspaceType defines the type of workspace
type WorkspaceType string

const (
	WorkspaceTypeGeneral     WorkspaceType = "general"
	WorkspaceTypePython      WorkspaceType = "python"
	WorkspaceTypeNodeJS      WorkspaceType = "nodejs"
	WorkspaceTypeGo          WorkspaceType = "go"
	WorkspaceTypeRust        WorkspaceType = "rust"
	WorkspaceTypeJava        WorkspaceType = "java"
	WorkspaceTypeCpp         WorkspaceType = "cpp"
	WorkspaceTypeWeb         WorkspaceType = "web"
	WorkspaceTypeDataScience WorkspaceType = "data_science"
	WorkspaceTypeML          WorkspaceType = "ml"
)

// WorkspaceStatus represents the current status of a workspace
type WorkspaceStatus string

const (
	WorkspaceStatusActive     WorkspaceStatus = "active"
	WorkspaceStatusInactive   WorkspaceStatus = "inactive"
	WorkspaceStatusCorrupted  WorkspaceStatus = "corrupted"
	WorkspaceStatusMaintenance WorkspaceStatus = "maintenance"
	WorkspaceStatusArchived   WorkspaceStatus = "archived"
)

// WorkspacePermissions defines access permissions for a workspace
type WorkspacePermissions struct {
	ReadOnly     bool     `json:"read_only"`
	AllowedUsers []string `json:"allowed_users,omitempty"`
	AllowedOps   []string `json:"allowed_operations"`
}

// WorkspaceStructure represents the directory structure of a workspace
type WorkspaceStructure struct {
	Directories map[string]*DirectoryInfo `json:"directories"`
	Files       map[string]*WorkspaceFileInfo      `json:"files"`
	Symlinks    map[string]*SymlinkInfo   `json:"symlinks"`
	TotalSize   int64                     `json:"total_size"`
	FileCount   int64                     `json:"file_count"`
	LastScan    time.Time                 `json:"last_scan"`
}

// DirectoryInfo represents information about a directory
type DirectoryInfo struct {
	Path        string            `json:"path"`
	Size        int64             `json:"size"`
	FileCount   int64             `json:"file_count"`
	Permissions string            `json:"permissions"`
	Owner       string            `json:"owner"`
	Group       string            `json:"group"`
	CreatedAt   time.Time         `json:"created_at"`
	ModifiedAt  time.Time         `json:"modified_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// WorkspaceFileInfo represents information about a file in workspace context
type WorkspaceFileInfo struct {
	Path        string            `json:"path"`
	Size        int64             `json:"size"`
	Checksum    string            `json:"checksum"`
	MimeType    string            `json:"mime_type"`
	Permissions string            `json:"permissions"`
	Owner       string            `json:"owner"`
	Group       string            `json:"group"`
	CreatedAt   time.Time         `json:"created_at"`
	ModifiedAt  time.Time         `json:"modified_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// SymlinkInfo represents information about a symbolic link
type SymlinkInfo struct {
	Path       string    `json:"path"`
	Target     string    `json:"target"`
	CreatedAt  time.Time `json:"created_at"`
	ModifiedAt time.Time `json:"modified_at"`
}

// ProjectTemplate defines a project template for workspace initialization
type ProjectTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        WorkspaceType          `json:"type"`
	Structure   []TemplateItem         `json:"structure"`
	Commands    []TemplateCommand      `json:"commands"`
	Variables   map[string]string      `json:"variables"`
	Metadata    map[string]interface{} `json:"metadata"`
	Version     string                 `json:"version"`
}

// TemplateItem represents an item in a project template
type TemplateItem struct {
	Type        string `json:"type"` // file, directory, symlink
	Path        string `json:"path"`
	Content     string `json:"content,omitempty"`
	Source      string `json:"source,omitempty"`
	Target      string `json:"target,omitempty"` // for symlinks
	Permissions string `json:"permissions,omitempty"`
	Variables   bool   `json:"variables"` // whether to process variables
}

// TemplateCommand represents a command to run during template initialization
type TemplateCommand struct {
	Name        string            `json:"name"`
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	WorkingDir  string            `json:"working_dir"`
	Environment map[string]string `json:"environment"`
	Timeout     time.Duration     `json:"timeout"`
	RunCondition string           `json:"run_condition,omitempty"`
}

// WorkspaceSnapshot represents a snapshot of workspace state
type WorkspaceSnapshot struct {
	ID           string                 `json:"id"`
	WorkspaceID  string                 `json:"workspace_id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	CreatedAt    time.Time              `json:"created_at"`
	Size         int64                  `json:"size"`
	FileCount    int64                  `json:"file_count"`
	Checksum     string                 `json:"checksum"`
	SnapshotPath string                 `json:"snapshot_path"`
	Metadata     map[string]interface{} `json:"metadata"`
	Compressed   bool                   `json:"compressed"`
}

// NewWorkspaceManager creates a new workspace manager
func NewWorkspaceManager(containerFS runtime.ContainerFS) *WorkspaceManager {
	wm := &WorkspaceManager{
		containerFS:      containerFS,
		workspaces:       make(map[string]*Workspace),
		templates:        make(map[string]*ProjectTemplate),
		snapshots:        make(map[string]*WorkspaceSnapshot),
		cleanupScheduler: NewCleanupScheduler(),
		sharingManager:   NewWorkspaceShareManager(),
	}

	// Initialize built-in templates
	wm.initializeBuiltinTemplates()

	// Start cleanup scheduler
	go wm.cleanupScheduler.Start(context.Background(), wm)

	return wm
}

// CreateWorkspace creates a new workspace with specified configuration
func (wm *WorkspaceManager) CreateWorkspace(ctx context.Context, config *WorkspaceConfig) (*Workspace, error) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	workspaceID := uuid.New().String()
	workspace := &Workspace{
		ID:           workspaceID,
		Name:         config.Name,
		Description:  config.Description,
		SandboxID:    config.SandboxID,
		ContainerID:  config.ContainerID,
		RootPath:     config.RootPath,
		Type:         config.Type,
		Template:     config.Template,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		LastAccessed: time.Now(),
		MaxSize:      config.MaxSize,
		MaxFiles:     config.MaxFiles,
		Structure:    &WorkspaceStructure{},
		Metadata:     make(map[string]interface{}),
		Tags:         config.Tags,
		Owner:        config.Owner,
		Permissions:  config.Permissions,
		Status:       WorkspaceStatusActive,
	}

	// Set defaults if not specified
	if workspace.MaxSize == 0 {
		workspace.MaxSize = 1024 * 1024 * 1024 // 1GB default
	}
	if workspace.MaxFiles == 0 {
		workspace.MaxFiles = 10000 // 10k files default
	}

	// Create workspace directory structure
	if err := wm.initializeWorkspaceStructure(ctx, workspace); err != nil {
		return nil, fmt.Errorf("failed to initialize workspace structure: %w", err)
	}

	// Apply template if specified
	if workspace.Template != "" {
		if err := wm.applyTemplate(ctx, workspace, workspace.Template, config.TemplateVars); err != nil {
			log.Warn().Err(err).Str("template", workspace.Template).Msg("Failed to apply template")
		}
	}

	// Calculate initial size and structure
	if err := wm.scanWorkspaceStructure(ctx, workspace); err != nil {
		log.Warn().Err(err).Str("workspace_id", workspaceID).Msg("Failed to scan workspace structure")
	}

	// Store workspace
	wm.workspaces[workspaceID] = workspace

	log.Info().
		Str("workspace_id", workspaceID).
		Str("name", workspace.Name).
		Str("type", string(workspace.Type)).
		Str("template", workspace.Template).
		Msg("Workspace created successfully")

	return workspace, nil
}

// GetWorkspace retrieves a workspace by ID
func (wm *WorkspaceManager) GetWorkspace(workspaceID string) (*Workspace, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	workspace, exists := wm.workspaces[workspaceID]
	if !exists {
		return nil, fmt.Errorf("workspace not found: %s", workspaceID)
	}

	// Update last accessed time
	workspace.LastAccessed = time.Now()

	return workspace, nil
}

// ListWorkspaces returns all workspaces, optionally filtered
func (wm *WorkspaceManager) ListWorkspaces(filter *WorkspaceFilter) ([]*Workspace, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	var workspaces []*Workspace
	for _, workspace := range wm.workspaces {
		if filter == nil || filter.Matches(workspace) {
			workspaces = append(workspaces, workspace)
		}
	}

	return workspaces, nil
}

// UpdateWorkspace updates workspace configuration
func (wm *WorkspaceManager) UpdateWorkspace(workspaceID string, updates *WorkspaceUpdates) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	workspace, exists := wm.workspaces[workspaceID]
	if !exists {
		return fmt.Errorf("workspace not found: %s", workspaceID)
	}

	// Apply updates
	if updates.Name != nil {
		workspace.Name = *updates.Name
	}
	if updates.Description != nil {
		workspace.Description = *updates.Description
	}
	if updates.MaxSize != nil {
		workspace.MaxSize = *updates.MaxSize
	}
	if updates.MaxFiles != nil {
		workspace.MaxFiles = *updates.MaxFiles
	}
	if updates.Tags != nil {
		workspace.Tags = updates.Tags
	}
	if updates.Metadata != nil {
		for k, v := range updates.Metadata {
			workspace.Metadata[k] = v
		}
	}
	if updates.Status != nil {
		workspace.Status = *updates.Status
	}

	workspace.UpdatedAt = time.Now()

	log.Info().
		Str("workspace_id", workspaceID).
		Str("name", workspace.Name).
		Msg("Workspace updated successfully")

	return nil
}

// DeleteWorkspace removes a workspace
func (wm *WorkspaceManager) DeleteWorkspace(ctx context.Context, workspaceID string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	workspace, exists := wm.workspaces[workspaceID]
	if !exists {
		return fmt.Errorf("workspace not found: %s", workspaceID)
	}

	// Remove workspace directory
	if err := wm.containerFS.RemoveDir(ctx, workspace.ContainerID, workspace.RootPath); err != nil {
		log.Warn().Err(err).Str("root_path", workspace.RootPath).Msg("Failed to remove workspace directory")
	}

	// Remove from tracking
	delete(wm.workspaces, workspaceID)

	// Clean up related snapshots
	for id, snapshot := range wm.snapshots {
		if snapshot.WorkspaceID == workspaceID {
			delete(wm.snapshots, id)
		}
	}

	log.Info().
		Str("workspace_id", workspaceID).
		Str("name", workspace.Name).
		Msg("Workspace deleted successfully")

	return nil
}

// initializeWorkspaceStructure creates the basic directory structure for a workspace
func (wm *WorkspaceManager) initializeWorkspaceStructure(ctx context.Context, workspace *Workspace) error {
	// Create root workspace directory
	if err := wm.containerFS.MakeDir(ctx, workspace.ContainerID, workspace.RootPath, 0755); err != nil {
		return fmt.Errorf("failed to create workspace root: %w", err)
	}

	// Create basic subdirectories
	basicDirs := []string{
		"src",     // Source code
		"docs",    // Documentation
		"tests",   // Test files
		"config",  // Configuration files
		"data",    // Data files
		"tmp",     // Temporary files
		"logs",    // Log files
	}

	for _, dir := range basicDirs {
		dirPath := path.Join(workspace.RootPath, dir)
		if err := wm.containerFS.MakeDir(ctx, workspace.ContainerID, dirPath, 0755); err != nil {
			log.Warn().Err(err).Str("dir_path", dirPath).Msg("Failed to create basic directory")
		}
	}

	// Create basic files
	readmePath := path.Join(workspace.RootPath, "README.md")
	readmeContent := fmt.Sprintf(`# %s

%s

## Directory Structure

- src/ - Source code files
- docs/ - Documentation
- tests/ - Test files
- config/ - Configuration files
- data/ - Data files
- tmp/ - Temporary files
- logs/ - Log files

---
*Workspace created: %s*
*Type: %s*
`, workspace.Name, workspace.Description, workspace.CreatedAt.Format(time.RFC3339), workspace.Type)

	if err := wm.containerFS.WriteFile(ctx, workspace.ContainerID, readmePath, []byte(readmeContent), 0644); err != nil {
		log.Warn().Err(err).Str("readme_path", readmePath).Msg("Failed to create README file")
	}

	return nil
}

// Configuration structs

// WorkspaceConfig holds configuration for creating a workspace
type WorkspaceConfig struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	SandboxID    string                 `json:"sandbox_id"`
	ContainerID  string                 `json:"container_id"`
	RootPath     string                 `json:"root_path"`
	Type         WorkspaceType          `json:"type"`
	Template     string                 `json:"template,omitempty"`
	TemplateVars map[string]string      `json:"template_vars,omitempty"`
	MaxSize      int64                  `json:"max_size"`
	MaxFiles     int64                  `json:"max_files"`
	Tags         []string               `json:"tags"`
	Owner        string                 `json:"owner"`
	Permissions  WorkspacePermissions   `json:"permissions"`
}

// WorkspaceFilter defines filters for listing workspaces
type WorkspaceFilter struct {
	Type     WorkspaceType   `json:"type,omitempty"`
	Status   WorkspaceStatus `json:"status,omitempty"`
	Owner    string          `json:"owner,omitempty"`
	Tags     []string        `json:"tags,omitempty"`
	SandboxID string         `json:"sandbox_id,omitempty"`
}

// Matches checks if a workspace matches the filter criteria
func (wf *WorkspaceFilter) Matches(workspace *Workspace) bool {
	if wf.Type != "" && workspace.Type != wf.Type {
		return false
	}
	if wf.Status != "" && workspace.Status != wf.Status {
		return false
	}
	if wf.Owner != "" && workspace.Owner != wf.Owner {
		return false
	}
	if wf.SandboxID != "" && workspace.SandboxID != wf.SandboxID {
		return false
	}
	if len(wf.Tags) > 0 {
		// Check if workspace has all required tags
		workspaceTags := make(map[string]bool)
		for _, tag := range workspace.Tags {
			workspaceTags[tag] = true
		}
		for _, requiredTag := range wf.Tags {
			if !workspaceTags[requiredTag] {
				return false
			}
		}
	}
	return true
}

// WorkspaceUpdates defines updates that can be applied to a workspace
type WorkspaceUpdates struct {
	Name        *string                `json:"name,omitempty"`
	Description *string                `json:"description,omitempty"`
	MaxSize     *int64                 `json:"max_size,omitempty"`
	MaxFiles    *int64                 `json:"max_files,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Status      *WorkspaceStatus       `json:"status,omitempty"`
}