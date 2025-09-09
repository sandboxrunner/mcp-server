package resources

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDiskController(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	
	assert.NotNil(t, controller)
	assert.Equal(t, tempDir, controller.basePath)
	assert.NotNil(t, controller.containers)
	assert.NotNil(t, controller.metrics)
	assert.NotNil(t, controller.metricsHistory)
	assert.Equal(t, uint32(1000), controller.projectIDCounter)
	assert.Equal(t, 100, controller.maxHistorySize)
}

func TestDiskController_ValidateDiskLimits(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)

	tests := []struct {
		name    string
		limits  *DiskLimits
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid limits",
			limits: &DiskLimits{
				SoftLimit: int64Ptr(500 * 1024 * 1024), // 500MB
				HardLimit: int64Ptr(1024 * 1024 * 1024), // 1GB
			},
			wantErr: false,
		},
		{
			name: "negative soft limit",
			limits: &DiskLimits{
				SoftLimit: int64Ptr(-1),
			},
			wantErr: true,
			errMsg:  "soft limit cannot be negative",
		},
		{
			name: "negative hard limit",
			limits: &DiskLimits{
				HardLimit: int64Ptr(-1),
			},
			wantErr: true,
			errMsg:  "hard limit cannot be negative",
		},
		{
			name: "soft limit exceeds hard limit",
			limits: &DiskLimits{
				SoftLimit: int64Ptr(2048),
				HardLimit: int64Ptr(1024),
			},
			wantErr: true,
			errMsg:  "soft limit cannot exceed hard limit",
		},
		{
			name: "negative inode soft limit",
			limits: &DiskLimits{
				InodeSoftLimit: int64Ptr(-1),
			},
			wantErr: true,
			errMsg:  "inode soft limit cannot be negative",
		},
		{
			name: "negative inode hard limit",
			limits: &DiskLimits{
				InodeHardLimit: int64Ptr(-1),
			},
			wantErr: true,
			errMsg:  "inode hard limit cannot be negative",
		},
		{
			name: "inode soft limit exceeds hard limit",
			limits: &DiskLimits{
				InodeSoftLimit: int64Ptr(2000),
				InodeHardLimit: int64Ptr(1000),
			},
			wantErr: true,
			errMsg:  "inode soft limit cannot exceed hard limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := controller.validateDiskLimits(tt.limits)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDiskController_ApplyDiskLimits(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	containerID := "test-container"

	tests := []struct {
		name    string
		limits  *DiskLimits
		wantErr bool
	}{
		{
			name: "apply basic disk limits",
			limits: &DiskLimits{
				SoftLimit: int64Ptr(500 * 1024 * 1024), // 500MB
				HardLimit: int64Ptr(1024 * 1024 * 1024), // 1GB
			},
			wantErr: false,
		},
		{
			name: "apply inode limits",
			limits: &DiskLimits{
				InodeSoftLimit: int64Ptr(1000),
				InodeHardLimit: int64Ptr(2000),
			},
			wantErr: false,
		},
		{
			name: "apply I/O throttling",
			limits: &DiskLimits{
				ReadBPS:  int64Ptr(100 * 1024 * 1024), // 100MB/s
				WriteBPS: int64Ptr(50 * 1024 * 1024),  // 50MB/s
				ReadIOPS: int64Ptr(1000),
				WriteIOPS: int64Ptr(500),
			},
			wantErr: false,
		},
		{
			name: "apply with cleanup enabled",
			limits: &DiskLimits{
				SoftLimit:     int64Ptr(1024 * 1024 * 1024), // 1GB
				EnableCleanup: boolPtr(true),
				GracePeriod:   int64Ptr(3600), // 1 hour
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := controller.ApplyDiskLimits(containerID, tt.limits)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				
				// Verify limits are stored
				controller.mu.RLock()
				storedLimits := controller.containers[containerID]
				controller.mu.RUnlock()
				
				assert.NotNil(t, storedLimits)
				assert.Equal(t, tt.limits.SoftLimit, storedLimits.SoftLimit)
				assert.Equal(t, tt.limits.HardLimit, storedLimits.HardLimit)
				
				// Verify container directory was created
				containerPath := filepath.Join(tempDir, containerID)
				_, err := os.Stat(containerPath)
				assert.NoError(t, err, "container directory should exist")
				
				// Check cleanup policy if enabled
				if tt.limits.EnableCleanup != nil && *tt.limits.EnableCleanup {
					controller.mu.RLock()
					policy := controller.cleanupPolicies[containerID]
					controller.mu.RUnlock()
					assert.NotNil(t, policy)
					assert.True(t, policy.Enabled)
				}
			}
		})
	}
}

func TestDiskController_GetDiskUsage(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	containerID := "test-container"

	// Create container directory
	containerPath := filepath.Join(tempDir, containerID)
	err = os.MkdirAll(containerPath, 0755)
	require.NoError(t, err)

	// Create some test files
	testFiles := []struct {
		path string
		size int
	}{
		{"file1.txt", 1024},
		{"file2.txt", 2048},
		{"subdir/file3.txt", 512},
		{"tmp/temp1.tmp", 256},
		{"logs/app.log", 1024},
		{"cache/cache1.dat", 4096},
	}

	for _, tf := range testFiles {
		filePath := filepath.Join(containerPath, tf.path)
		err = os.MkdirAll(filepath.Dir(filePath), 0755)
		require.NoError(t, err)
		
		data := make([]byte, tf.size)
		err = os.WriteFile(filePath, data, 0644)
		require.NoError(t, err)
	}

	metrics, err := controller.GetDiskUsage(containerID)
	assert.NoError(t, err)
	assert.NotNil(t, metrics)
	assert.Equal(t, containerID, metrics.ContainerID)
	assert.Greater(t, metrics.TotalBytes, int64(0))
	assert.Greater(t, metrics.TotalInodes, int64(0))
	assert.GreaterOrEqual(t, metrics.FileCount, int64(6)) // At least our test files
	assert.GreaterOrEqual(t, metrics.DirCount, int64(4))  // At least our test dirs
	assert.Greater(t, metrics.TempDirUsage, int64(0))      // tmp dir has content
	assert.Greater(t, metrics.LogDirUsage, int64(0))       // logs dir has content  
	assert.Greater(t, metrics.CacheDirUsage, int64(0))     // cache dir has content
}

func TestDiskController_GetDiskStats(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	containerID := "test-container"

	// Create container directory
	containerPath := filepath.Join(tempDir, containerID)
	err = os.MkdirAll(containerPath, 0755)
	require.NoError(t, err)

	stats, err := controller.GetDiskStats(containerID)
	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.NotEmpty(t, stats.Device)
	assert.NotEmpty(t, stats.MountPoint)
	assert.NotEmpty(t, stats.FilesystemType)
	assert.Greater(t, stats.BlockSize, int64(0))
	assert.Greater(t, stats.TotalBlocks, int64(0))
	assert.GreaterOrEqual(t, stats.FreeBlocks, int64(0))
	assert.GreaterOrEqual(t, stats.AvailableBlocks, int64(0))
	assert.Greater(t, stats.TotalInodes, int64(0))
	assert.GreaterOrEqual(t, stats.FreeInodes, int64(0))
	assert.NotNil(t, stats.IOStats)
}

func TestDiskController_SetupCleanupPolicy(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	containerID := "test-container"

	policy := &CleanupPolicy{
		Enabled:          true,
		ThresholdPercent: 85.0,
		RetentionPeriod:  24 * time.Hour,
		FilePatterns:     []string{"*.tmp", "*.log"},
		Directories:      []string{"tmp", "logs"},
		PreserveCount:    5,
		SortBy:           "mtime",
		DryRun:           false,
	}

	err = controller.SetupCleanupPolicy(containerID, policy)
	assert.NoError(t, err)

	// Verify policy is stored
	controller.mu.RLock()
	storedPolicy := controller.cleanupPolicies[containerID]
	controller.mu.RUnlock()
	
	assert.NotNil(t, storedPolicy)
	assert.Equal(t, policy.Enabled, storedPolicy.Enabled)
	assert.Equal(t, policy.ThresholdPercent, storedPolicy.ThresholdPercent)
	assert.Equal(t, policy.RetentionPeriod, storedPolicy.RetentionPeriod)
}

func TestDiskController_RunCleanup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	containerID := "test-container"

	// Set up container directory
	containerPath := filepath.Join(tempDir, containerID)
	err = os.MkdirAll(containerPath, 0755)
	require.NoError(t, err)

	// Create tmp directory with old files
	tmpDir := filepath.Join(containerPath, "tmp")
	err = os.MkdirAll(tmpDir, 0755)
	require.NoError(t, err)

	// Create files with different ages
	oldTime := time.Now().Add(-48 * time.Hour) // 2 days old
	recentTime := time.Now().Add(-1 * time.Hour) // 1 hour old

	oldFiles := []string{"old1.tmp", "old2.tmp", "old3.log"}
	recentFiles := []string{"recent1.tmp", "recent2.log"}

	for _, filename := range oldFiles {
		filePath := filepath.Join(tmpDir, filename)
		err = os.WriteFile(filePath, []byte("test content"), 0644)
		require.NoError(t, err)
		err = os.Chtimes(filePath, oldTime, oldTime)
		require.NoError(t, err)
	}

	for _, filename := range recentFiles {
		filePath := filepath.Join(tmpDir, filename)
		err = os.WriteFile(filePath, []byte("test content"), 0644)
		require.NoError(t, err)
		err = os.Chtimes(filePath, recentTime, recentTime)
		require.NoError(t, err)
	}

	// Set up cleanup policy
	policy := &CleanupPolicy{
		Enabled:         true,
		ThresholdPercent: 50.0,
		RetentionPeriod: 24 * time.Hour, // Files older than 1 day
		FilePatterns:    []string{"*.tmp", "*.log"},
		Directories:     []string{"tmp"},
		PreserveCount:   1, // Keep at least 1 file
		SortBy:          "mtime",
		DryRun:          false,
	}
	
	err = controller.SetupCleanupPolicy(containerID, policy)
	require.NoError(t, err)

	// Run cleanup
	result, err := controller.RunCleanup(containerID)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	
	// Should have removed some old files but preserved at least 1
	assert.Greater(t, result.FilesRemoved, 0)
	assert.LessOrEqual(t, result.FilesRemoved, len(oldFiles)-1) // At least 1 preserved

	// Check that recent files are still there
	for _, filename := range recentFiles {
		filePath := filepath.Join(tmpDir, filename)
		_, err := os.Stat(filePath)
		assert.NoError(t, err, "recent file should not be removed")
	}
}

func TestDiskController_GetDiskHistory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	containerID := "test-container"

	// Initially empty
	history := controller.GetDiskHistory(containerID)
	assert.Empty(t, history)

	// Add some mock metrics
	now := time.Now()
	for i := 0; i < 5; i++ {
		metrics := &DiskMetrics{
			ContainerID:    containerID,
			Timestamp:      now.Add(time.Duration(i) * time.Minute),
			UsedBytes:      int64(100*1024*1024 + i*10*1024*1024), // Growing usage
			UsagePercent:   float64(10 + i*2),
			FileCount:      int64(100 + i*10),
		}
		controller.storeMetrics(containerID, metrics)
	}

	history = controller.GetDiskHistory(containerID)
	assert.Len(t, history, 5)
	
	// Verify order (should be chronological)
	for i := 0; i < 4; i++ {
		assert.True(t, history[i].Timestamp.Before(history[i+1].Timestamp))
		assert.Less(t, history[i].UsedBytes, history[i+1].UsedBytes)
	}
}

func TestDiskController_RemoveDiskLimits(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	containerID := "test-container"

	// Apply some limits first
	limits := &DiskLimits{
		SoftLimit: int64Ptr(500 * 1024 * 1024), // 500MB
		HardLimit: int64Ptr(1024 * 1024 * 1024), // 1GB
	}
	err = controller.ApplyDiskLimits(containerID, limits)
	require.NoError(t, err)

	// Verify limits are stored
	controller.mu.RLock()
	_, exists := controller.containers[containerID]
	controller.mu.RUnlock()
	assert.True(t, exists)

	// Remove limits
	err = controller.RemoveDiskLimits(containerID)
	assert.NoError(t, err)

	// Verify cleanup
	controller.mu.RLock()
	_, exists = controller.containers[containerID]
	_, metricsExists := controller.metrics[containerID]
	_, historyExists := controller.metricsHistory[containerID]
	_, policyExists := controller.cleanupPolicies[containerID]
	_, ioExists := controller.ioThrottling[containerID]
	controller.mu.RUnlock()

	assert.False(t, exists)
	assert.False(t, metricsExists)
	assert.False(t, historyExists)
	assert.False(t, policyExists)
	assert.False(t, ioExists)
}

func TestDiskController_CountFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)

	// Create test directory structure
	testStructure := map[string]string{
		"file1.txt":         "content1",
		"file2.txt":         "content2",
		"subdir/file3.txt":  "content3",
		"subdir/file4.txt":  "content4",
		"subdir2/file5.txt": "content5",
	}

	for filePath, content := range testStructure {
		fullPath := filepath.Join(tempDir, filePath)
		err = os.MkdirAll(filepath.Dir(fullPath), 0755)
		require.NoError(t, err)
		err = os.WriteFile(fullPath, []byte(content), 0644)
		require.NoError(t, err)
	}

	// Create a symbolic link
	linkPath := filepath.Join(tempDir, "link1")
	err = os.Symlink("file1.txt", linkPath)
	require.NoError(t, err)

	files, dirs, links, err := controller.countFiles(tempDir)
	assert.NoError(t, err)
	assert.Equal(t, int64(5), files) // 5 regular files
	assert.GreaterOrEqual(t, dirs, int64(2)) // At least 2 subdirectories (subdir, subdir2)
	assert.Equal(t, int64(1), links) // 1 symbolic link
}

func TestDiskController_GetDirSize(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)

	// Create test files with known sizes
	testFiles := map[string]int{
		"file1.txt":        1024,
		"file2.txt":        2048,
		"subdir/file3.txt": 512,
	}

	expectedSize := int64(0)
	for filePath, size := range testFiles {
		fullPath := filepath.Join(tempDir, filePath)
		err = os.MkdirAll(filepath.Dir(fullPath), 0755)
		require.NoError(t, err)
		
		data := make([]byte, size)
		err = os.WriteFile(fullPath, data, 0644)
		require.NoError(t, err)
		expectedSize += int64(size)
	}

	actualSize, err := controller.getDirSize(tempDir)
	assert.NoError(t, err)
	assert.Equal(t, expectedSize, actualSize)
}

func TestDiskController_CreateDefaultCleanupPolicy(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)

	tests := []struct {
		name   string
		limits *DiskLimits
	}{
		{
			name:   "default policy",
			limits: &DiskLimits{},
		},
		{
			name: "with grace period",
			limits: &DiskLimits{
				GracePeriod: int64Ptr(3600), // 1 hour
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := controller.createDefaultCleanupPolicy(tt.limits)
			
			assert.NotNil(t, policy)
			assert.True(t, policy.Enabled)
			assert.Equal(t, 80.0, policy.ThresholdPercent)
			assert.Contains(t, policy.FilePatterns, "*.tmp")
			assert.Contains(t, policy.Directories, "tmp")
			assert.Equal(t, 10, policy.PreserveCount)
			assert.Equal(t, "atime", policy.SortBy)
			assert.False(t, policy.DryRun)
			
			if tt.limits.GracePeriod != nil {
				expectedDuration := time.Duration(*tt.limits.GracePeriod) * time.Second
				assert.Equal(t, expectedDuration, policy.RetentionPeriod)
			} else {
				assert.Equal(t, 7*24*time.Hour, policy.RetentionPeriod)
			}
		})
	}
}

func TestDiskController_GetSystemDiskInfo(t *testing.T) {
	info, err := GetSystemDiskInfo()
	
	// This test might fail in some environments where /proc/mounts is not available
	if err != nil {
		t.Skipf("Skipping system disk info test: %v", err)
		return
	}
	
	assert.NoError(t, err)
	assert.NotNil(t, info)
	
	// Check that we got mount information
	if mounts, ok := info["mounts"]; ok {
		mountsList := mounts.([]map[string]interface{})
		assert.NotEmpty(t, mountsList)
		
		// Check first mount has required fields
		if len(mountsList) > 0 {
			mount := mountsList[0]
			assert.Contains(t, mount, "device")
			assert.Contains(t, mount, "mountpoint")
			assert.Contains(t, mount, "fstype")
		}
	}
}

func TestDiskController_StoreMetrics(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	containerID := "test-container"

	// Store metrics beyond the max history size
	for i := 0; i < controller.maxHistorySize+10; i++ {
		metrics := &DiskMetrics{
			ContainerID:  containerID,
			Timestamp:    time.Now().Add(time.Duration(i) * time.Second),
			UsedBytes:    int64((i % 100) * 1024 * 1024),
			UsagePercent: float64(i % 100),
			FileCount:    int64(100 + i),
		}
		controller.storeMetrics(containerID, metrics)
	}

	controller.mu.RLock()
	history := controller.metricsHistory[containerID]
	current := controller.metrics[containerID]
	controller.mu.RUnlock()

	// Should not exceed max history size
	assert.LessOrEqual(t, len(history), controller.maxHistorySize)
	assert.NotNil(t, current)
	assert.Equal(t, containerID, current.ContainerID)
}

// Test cleanup dry run
func TestDiskController_RunCleanupDryRun(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "disk_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	containerID := "test-container"

	// Set up container directory with old files
	containerPath := filepath.Join(tempDir, containerID)
	tmpDir := filepath.Join(containerPath, "tmp")
	err = os.MkdirAll(tmpDir, 0755)
	require.NoError(t, err)

	// Create old files
	oldTime := time.Now().Add(-48 * time.Hour)
	oldFiles := []string{"old1.tmp", "old2.tmp", "old3.log"}

	for _, filename := range oldFiles {
		filePath := filepath.Join(tmpDir, filename)
		err = os.WriteFile(filePath, []byte("test content"), 0644)
		require.NoError(t, err)
		err = os.Chtimes(filePath, oldTime, oldTime)
		require.NoError(t, err)
	}

	// Set up cleanup policy with dry run enabled
	policy := &CleanupPolicy{
		Enabled:         true,
		RetentionPeriod: 24 * time.Hour,
		FilePatterns:    []string{"*.tmp", "*.log"},
		Directories:     []string{"tmp"},
		PreserveCount:   0,
		SortBy:          "mtime",
		DryRun:          true, // Dry run - don't actually delete
	}
	
	err = controller.SetupCleanupPolicy(containerID, policy)
	require.NoError(t, err)

	// Run cleanup
	result, err := controller.RunCleanup(containerID)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	
	// Should report files that would be removed, but not actually remove them
	assert.Equal(t, len(oldFiles), result.FilesRemoved)
	assert.Equal(t, int64(0), result.SpaceFreed) // No space actually freed in dry run

	// Check that files still exist
	for _, filename := range oldFiles {
		filePath := filepath.Join(tmpDir, filename)
		_, err := os.Stat(filePath)
		assert.NoError(t, err, "files should still exist in dry run")
	}
}

// Helper functions for tests

func boolPtr(b bool) *bool {
	return &b
}

// Benchmark tests

func BenchmarkDiskController_ApplyDiskLimits(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "disk_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	limits := &DiskLimits{
		SoftLimit: int64Ptr(500 * 1024 * 1024),
		HardLimit: int64Ptr(1024 * 1024 * 1024),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		containerID := "container-" + strconv.Itoa(i)
		err := controller.ApplyDiskLimits(containerID, limits)
		if err != nil {
			b.Fatalf("ApplyDiskLimits failed: %v", err)
		}
	}
}

func BenchmarkDiskController_GetDiskUsage(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "disk_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	containerID := "test-container"

	// Set up test container directory
	containerPath := filepath.Join(tempDir, containerID)
	err = os.MkdirAll(containerPath, 0755)
	require.NoError(b, err)

	// Create some test files
	for i := 0; i < 10; i++ {
		filePath := filepath.Join(containerPath, "file"+strconv.Itoa(i)+".txt")
		data := make([]byte, 1024)
		err = os.WriteFile(filePath, data, 0644)
		require.NoError(b, err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := controller.GetDiskUsage(containerID)
		if err != nil {
			b.Fatalf("GetDiskUsage failed: %v", err)
		}
	}
}

func BenchmarkDiskController_CountFiles(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "disk_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)

	// Create test directory with many files
	for i := 0; i < 100; i++ {
		filePath := filepath.Join(tempDir, "file"+strconv.Itoa(i)+".txt")
		err = os.WriteFile(filePath, []byte("content"), 0644)
		require.NoError(b, err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err := controller.countFiles(tempDir)
		if err != nil {
			b.Fatalf("countFiles failed: %v", err)
		}
	}
}