package languages

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CompilerInterface defines the interface for language-specific compilers
type CompilerInterface interface {
	// Compile compiles source code and returns compilation result
	Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error)
	
	// GetSupportedLanguages returns languages supported by this compiler
	GetSupportedLanguages() []Language
	
	// GetCompilerVersion returns the version of the compiler
	GetCompilerVersion(ctx context.Context) (string, error)
	
	// ValidateCompilerAvailability checks if the compiler is available
	ValidateCompilerAvailability(ctx context.Context) error
}

// CompilationRequest contains compilation parameters
type CompilationRequest struct {
	Language        Language          `json:"language"`
	SourceCode      string            `json:"source_code"`
	SourceFiles     map[string]string `json:"source_files,omitempty"`
	WorkingDir      string            `json:"working_dir"`
	OutputPath      string            `json:"output_path,omitempty"`
	CompilerFlags   []string          `json:"compiler_flags,omitempty"`
	LinkerFlags     []string          `json:"linker_flags,omitempty"`
	OptimizationLevel string          `json:"optimization_level,omitempty"`
	DebugSymbols    bool              `json:"debug_symbols,omitempty"`
	TargetArch      string            `json:"target_arch,omitempty"`
	TargetOS        string            `json:"target_os,omitempty"`
	BuildMode       string            `json:"build_mode,omitempty"` // debug, release
	Environment     map[string]string `json:"environment,omitempty"`
	Timeout         time.Duration     `json:"timeout,omitempty"`
	CacheEnabled    bool              `json:"cache_enabled,omitempty"`
	CustomConfig    map[string]string `json:"custom_config,omitempty"`
}

// CompilationResponse contains compilation results
type CompilationResponse struct {
	Success         bool              `json:"success"`
	ExecutablePath  string            `json:"executable_path,omitempty"`
	ArtifactPaths   []string          `json:"artifact_paths,omitempty"`
	Output          string            `json:"output"`
	ErrorOutput     string            `json:"error_output,omitempty"`
	Duration        time.Duration     `json:"duration"`
	CacheHit        bool              `json:"cache_hit"`
	CacheKey        string            `json:"cache_key,omitempty"`
	CompilerVersion string            `json:"compiler_version,omitempty"`
	Warnings        []CompilerWarning `json:"warnings,omitempty"`
	Error           error             `json:"error,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// CompilerWarning represents a compiler warning
type CompilerWarning struct {
	Message    string `json:"message"`
	File       string `json:"file,omitempty"`
	Line       int    `json:"line,omitempty"`
	Column     int    `json:"column,omitempty"`
	Severity   string `json:"severity"` // warning, error, note
	Code       string `json:"code,omitempty"`
}

// CompilationCache manages compilation caching
type CompilationCache struct {
	cacheDir    string
	maxAge      time.Duration
	maxSize     int64
	mu          sync.RWMutex
	entries     map[string]*CacheEntry
	totalSize   int64
	enabled     bool
}

// CacheEntry represents a cached compilation result
type CacheEntry struct {
	Key           string            `json:"key"`
	Language      Language          `json:"language"`
	SourceHash    string            `json:"source_hash"`
	CompilerHash  string            `json:"compiler_hash"`
	ExecutablePath string           `json:"executable_path"`
	ArtifactPaths []string          `json:"artifact_paths"`
	CreatedAt     time.Time         `json:"created_at"`
	AccessedAt    time.Time         `json:"accessed_at"`
	Size          int64             `json:"size"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// CompilerManager manages multiple language compilers
type CompilerManager struct {
	compilers map[Language]CompilerInterface
	cache     *CompilationCache
	metrics   map[string]interface{}
	mu        sync.RWMutex
}

// NewCompilerManager creates a new compiler manager
func NewCompilerManager(cacheDir string, enableCache bool) *CompilerManager {
	cache := NewCompilationCache(cacheDir, enableCache)
	
	manager := &CompilerManager{
		compilers: make(map[Language]CompilerInterface),
		cache:     cache,
		metrics:   make(map[string]interface{}),
	}
	
	// Register default compilers
	manager.registerDefaultCompilers()
	
	return manager
}

// NewCompilationCache creates a new compilation cache
func NewCompilationCache(cacheDir string, enabled bool) *CompilationCache {
	cache := &CompilationCache{
		cacheDir:  cacheDir,
		maxAge:    24 * time.Hour, // 24 hours default
		maxSize:   1024 * 1024 * 1024, // 1GB default
		entries:   make(map[string]*CacheEntry),
		totalSize: 0,
		enabled:   enabled,
	}
	
	if enabled {
		// Create cache directory
		if err := os.MkdirAll(cacheDir, 0755); err == nil {
			cache.loadCache()
		}
	}
	
	return cache
}

// Compile performs compilation with caching support
func (cm *CompilerManager) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	startTime := time.Now()
	
	// Get compiler for language
	compiler, exists := cm.compilers[request.Language]
	if !exists {
		return &CompilationResponse{
			Success: false,
			Error:   fmt.Errorf("no compiler available for language: %s", request.Language),
		}, nil
	}
	
	// Generate cache key
	cacheKey := cm.generateCacheKey(request)
	
	// Check cache if enabled
	if request.CacheEnabled && cm.cache.enabled {
		if cachedResult, found := cm.cache.Get(cacheKey); found {
			// Verify cached artifacts still exist
			if cm.verifyCachedArtifacts(cachedResult) {
				cm.updateMetrics("cache_hit", 1)
				return &CompilationResponse{
					Success:        true,
					ExecutablePath: cachedResult.ExecutablePath,
					ArtifactPaths:  cachedResult.ArtifactPaths,
					Duration:       time.Since(startTime),
					CacheHit:       true,
					CacheKey:       cacheKey,
					Metadata:       cachedResult.Metadata,
				}, nil
			} else {
				// Remove invalid cache entry
				cm.cache.Delete(cacheKey)
			}
		}
	}
	
	// Perform compilation
	response, err := compiler.Compile(ctx, request)
	if err != nil {
		return response, err
	}
	
	response.CacheKey = cacheKey
	response.Duration = time.Since(startTime)
	
	// Cache successful compilation if enabled
	if request.CacheEnabled && cm.cache.enabled && response.Success {
		cacheEntry := &CacheEntry{
			Key:           cacheKey,
			Language:      request.Language,
			SourceHash:    cm.hashString(request.SourceCode),
			ExecutablePath: response.ExecutablePath,
			ArtifactPaths: response.ArtifactPaths,
			CreatedAt:     time.Now(),
			AccessedAt:    time.Now(),
			Metadata:      response.Metadata,
		}
		
		// Calculate size of artifacts
		cacheEntry.Size = cm.calculateArtifactSize(response.ArtifactPaths)
		
		cm.cache.Put(cacheKey, cacheEntry)
	}
	
	// Update metrics
	cm.updateMetrics("compilation_count", 1)
	cm.updateMetrics("compilation_duration", response.Duration)
	if response.Success {
		cm.updateMetrics("successful_compilations", 1)
	} else {
		cm.updateMetrics("failed_compilations", 1)
	}
	
	return response, nil
}

// RegisterCompiler registers a compiler for a specific language
func (cm *CompilerManager) RegisterCompiler(language Language, compiler CompilerInterface) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.compilers[language] = compiler
}

// GetCompiler returns the compiler for a specific language
func (cm *CompilerManager) GetCompiler(language Language) (CompilerInterface, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	compiler, exists := cm.compilers[language]
	return compiler, exists
}

// GetSupportedLanguages returns all supported languages
func (cm *CompilerManager) GetSupportedLanguages() []Language {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	languages := make([]Language, 0, len(cm.compilers))
	for lang := range cm.compilers {
		languages = append(languages, lang)
	}
	return languages
}

// Cache operations
func (cc *CompilationCache) Get(key string) (*CacheEntry, bool) {
	if !cc.enabled {
		return nil, false
	}
	
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	
	entry, exists := cc.entries[key]
	if !exists {
		return nil, false
	}
	
	// Check if entry is expired
	if time.Since(entry.CreatedAt) > cc.maxAge {
		// Remove expired entry (defer to avoid deadlock)
		go func() {
			cc.mu.Lock()
			defer cc.mu.Unlock()
			delete(cc.entries, key)
			cc.totalSize -= entry.Size
		}()
		return nil, false
	}
	
	// Update access time
	entry.AccessedAt = time.Now()
	
	return entry, true
}

func (cc *CompilationCache) Put(key string, entry *CacheEntry) {
	if !cc.enabled {
		return
	}
	
	cc.mu.Lock()
	defer cc.mu.Unlock()
	
	// Remove existing entry if it exists
	if existing, exists := cc.entries[key]; exists {
		cc.totalSize -= existing.Size
	}
	
	// Check if cache is full and evict if necessary
	if cc.totalSize+entry.Size > cc.maxSize {
		cc.evictLRU()
	}
	
	cc.entries[key] = entry
	cc.totalSize += entry.Size
	
	// Persist cache entry to disk
	cc.persistEntry(key, entry)
}

func (cc *CompilationCache) Delete(key string) {
	if !cc.enabled {
		return
	}
	
	cc.mu.Lock()
	defer cc.mu.Unlock()
	
	if entry, exists := cc.entries[key]; exists {
		delete(cc.entries, key)
		cc.totalSize -= entry.Size
		
		// Remove from disk
		cc.removeEntry(key)
	}
}

func (cc *CompilationCache) Clear() {
	if !cc.enabled {
		return
	}
	
	cc.mu.Lock()
	defer cc.mu.Unlock()
	
	cc.entries = make(map[string]*CacheEntry)
	cc.totalSize = 0
	
	// Clear disk cache
	os.RemoveAll(cc.cacheDir)
	os.MkdirAll(cc.cacheDir, 0755)
}

func (cc *CompilationCache) Stats() map[string]interface{} {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	
	return map[string]interface{}{
		"enabled":     cc.enabled,
		"entry_count": len(cc.entries),
		"total_size":  cc.totalSize,
		"max_size":    cc.maxSize,
		"max_age":     cc.maxAge,
		"cache_dir":   cc.cacheDir,
	}
}

// Private helper methods
func (cm *CompilerManager) registerDefaultCompilers() {
	// Register built-in compilers
	cm.RegisterCompiler(LanguageC, NewCCompiler())
	cm.RegisterCompiler(LanguageCPP, NewCppCompiler())
	cm.RegisterCompiler(LanguageGo, NewGoCompiler())
	cm.RegisterCompiler(LanguageRust, NewRustCompiler())
	cm.RegisterCompiler(LanguageJava, NewJavaCompiler())
	cm.RegisterCompiler(LanguageCSharp, NewCSharpCompiler())
}

func (cm *CompilerManager) generateCacheKey(request *CompilationRequest) string {
	// Create a deterministic hash based on compilation parameters
	hasher := sha256.New()
	
	// Include source code
	hasher.Write([]byte(request.SourceCode))
	
	// Include source files
	for filename, content := range request.SourceFiles {
		hasher.Write([]byte(filename))
		hasher.Write([]byte(content))
	}
	
	// Include compilation parameters
	hasher.Write([]byte(string(request.Language)))
	hasher.Write([]byte(strings.Join(request.CompilerFlags, ",")))
	hasher.Write([]byte(strings.Join(request.LinkerFlags, ",")))
	hasher.Write([]byte(request.OptimizationLevel))
	hasher.Write([]byte(fmt.Sprintf("%v", request.DebugSymbols)))
	hasher.Write([]byte(request.TargetArch))
	hasher.Write([]byte(request.TargetOS))
	hasher.Write([]byte(request.BuildMode))
	
	// Include compiler version (if available)
	if compiler, exists := cm.compilers[request.Language]; exists {
		if version, err := compiler.GetCompilerVersion(context.Background()); err == nil {
			hasher.Write([]byte(version))
		}
	}
	
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func (cm *CompilerManager) verifyCachedArtifacts(entry *CacheEntry) bool {
	// Check if executable exists
	if entry.ExecutablePath != "" {
		if _, err := os.Stat(entry.ExecutablePath); os.IsNotExist(err) {
			return false
		}
	}
	
	// Check if artifact paths exist
	for _, artifactPath := range entry.ArtifactPaths {
		if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
			return false
		}
	}
	
	return true
}

func (cm *CompilerManager) calculateArtifactSize(artifactPaths []string) int64 {
	var totalSize int64
	
	for _, path := range artifactPaths {
		if info, err := os.Stat(path); err == nil {
			totalSize += info.Size()
		}
	}
	
	return totalSize
}

func (cm *CompilerManager) hashString(s string) string {
	hasher := sha256.New()
	hasher.Write([]byte(s))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func (cm *CompilerManager) updateMetrics(key string, value interface{}) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.metrics[key] = value
}

func (cc *CompilationCache) evictLRU() {
	if len(cc.entries) == 0 {
		return
	}
	
	// Find least recently used entry
	var oldestKey string
	var oldestTime time.Time = time.Now()
	
	for key, entry := range cc.entries {
		if entry.AccessedAt.Before(oldestTime) {
			oldestTime = entry.AccessedAt
			oldestKey = key
		}
	}
	
	// Remove oldest entry
	if oldestKey != "" {
		if entry, exists := cc.entries[oldestKey]; exists {
			delete(cc.entries, oldestKey)
			cc.totalSize -= entry.Size
			cc.removeEntry(oldestKey)
		}
	}
}

func (cc *CompilationCache) loadCache() {
	cacheIndexPath := filepath.Join(cc.cacheDir, "index.json")
	
	data, err := os.ReadFile(cacheIndexPath)
	if err != nil {
		return // Cache index doesn't exist yet
	}
	
	var entries map[string]*CacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return // Invalid cache index
	}
	
	// Load valid entries
	now := time.Now()
	for key, entry := range entries {
		// Skip expired entries
		if now.Sub(entry.CreatedAt) > cc.maxAge {
			continue
		}
		
		// Verify artifacts still exist
		if cc.artifactsExist(entry) {
			cc.entries[key] = entry
			cc.totalSize += entry.Size
		}
	}
}

func (cc *CompilationCache) persistEntry(key string, entry *CacheEntry) {
	cacheIndexPath := filepath.Join(cc.cacheDir, "index.json")
	
	// Save cache index
	data, err := json.MarshalIndent(cc.entries, "", "  ")
	if err != nil {
		return
	}
	
	os.WriteFile(cacheIndexPath, data, 0644)
}

func (cc *CompilationCache) removeEntry(key string) {
	// Remove entry from index and update file
	cacheIndexPath := filepath.Join(cc.cacheDir, "index.json")
	
	data, err := json.MarshalIndent(cc.entries, "", "  ")
	if err != nil {
		return
	}
	
	os.WriteFile(cacheIndexPath, data, 0644)
}

func (cc *CompilationCache) artifactsExist(entry *CacheEntry) bool {
	if entry.ExecutablePath != "" {
		if _, err := os.Stat(entry.ExecutablePath); os.IsNotExist(err) {
			return false
		}
	}
	
	for _, path := range entry.ArtifactPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return false
		}
	}
	
	return true
}

// Specific compiler implementations (stubs - these would be implemented separately)

type CCompiler struct {
	command string
	version string
}

func NewCCompiler() *CCompiler {
	return &CCompiler{command: "gcc"}
}

func (c *CCompiler) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	// Implementation would go here
	return &CompilationResponse{Success: false, Error: fmt.Errorf("not implemented")}, nil
}

func (c *CCompiler) GetSupportedLanguages() []Language {
	return []Language{LanguageC}
}

func (c *CCompiler) GetCompilerVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, c.command, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (c *CCompiler) ValidateCompilerAvailability(ctx context.Context) error {
	_, err := exec.LookPath(c.command)
	return err
}

// Similar implementations for other compilers...

type CppCompiler struct {
	command string
}

func NewCppCompiler() *CppCompiler {
	return &CppCompiler{command: "g++"}
}

func (c *CppCompiler) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	return &CompilationResponse{Success: false, Error: fmt.Errorf("not implemented")}, nil
}

func (c *CppCompiler) GetSupportedLanguages() []Language {
	return []Language{LanguageCPP}
}

func (c *CppCompiler) GetCompilerVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, c.command, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (c *CppCompiler) ValidateCompilerAvailability(ctx context.Context) error {
	_, err := exec.LookPath(c.command)
	return err
}

type GoCompiler struct {
	command string
}

func NewGoCompiler() *GoCompiler {
	return &GoCompiler{command: "go"}
}

func (c *GoCompiler) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	return &CompilationResponse{Success: false, Error: fmt.Errorf("not implemented")}, nil
}

func (c *GoCompiler) GetSupportedLanguages() []Language {
	return []Language{LanguageGo}
}

func (c *GoCompiler) GetCompilerVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, c.command, "version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (c *GoCompiler) ValidateCompilerAvailability(ctx context.Context) error {
	_, err := exec.LookPath(c.command)
	return err
}

type RustCompiler struct {
	command string
}

func NewRustCompiler() *RustCompiler {
	return &RustCompiler{command: "rustc"}
}

func (c *RustCompiler) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	return &CompilationResponse{Success: false, Error: fmt.Errorf("not implemented")}, nil
}

func (c *RustCompiler) GetSupportedLanguages() []Language {
	return []Language{LanguageRust}
}

func (c *RustCompiler) GetCompilerVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, c.command, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (c *RustCompiler) ValidateCompilerAvailability(ctx context.Context) error {
	_, err := exec.LookPath(c.command)
	return err
}

type JavaCompiler struct {
	command string
}

func NewJavaCompiler() *JavaCompiler {
	return &JavaCompiler{command: "javac"}
}

func (c *JavaCompiler) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	return &CompilationResponse{Success: false, Error: fmt.Errorf("not implemented")}, nil
}

func (c *JavaCompiler) GetSupportedLanguages() []Language {
	return []Language{LanguageJava}
}

func (c *JavaCompiler) GetCompilerVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, c.command, "-version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (c *JavaCompiler) ValidateCompilerAvailability(ctx context.Context) error {
	_, err := exec.LookPath(c.command)
	return err
}

type CSharpCompiler struct {
	command string
}

func NewCSharpCompiler() *CSharpCompiler {
	return &CSharpCompiler{command: "dotnet"}
}

func (c *CSharpCompiler) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	return &CompilationResponse{Success: false, Error: fmt.Errorf("not implemented")}, nil
}

func (c *CSharpCompiler) GetSupportedLanguages() []Language {
	return []Language{LanguageCSharp}
}

func (c *CSharpCompiler) GetCompilerVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, c.command, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (c *CSharpCompiler) ValidateCompilerAvailability(ctx context.Context) error {
	_, err := exec.LookPath(c.command)
	return err
}