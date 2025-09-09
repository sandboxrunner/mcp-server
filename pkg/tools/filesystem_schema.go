package tools

// EnhancedFileContentSchema returns the enhanced schema for file content operations
func EnhancedFileContentSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
				"pattern":     "^[a-zA-Z0-9-]+$",
			},
			"path": map[string]interface{}{
				"type":        "string",
				"description": "The file path within the sandbox container",
				"pattern":     "^/.*",
				"maxLength":   1024,
			},
			"content": map[string]interface{}{
				"type":        "string",
				"description": "The file content to write",
				"maxLength":   10485760, // 10MB in base64
			},
			"encoding": map[string]interface{}{
				"type":        "string",
				"description": "Content encoding (base64 or utf8)",
				"enum":        []string{"base64", "utf8"},
				"default":     "utf8",
			},
			"mode": map[string]interface{}{
				"type":        "string",
				"description": "File permissions in octal format (e.g., '0644')",
				"pattern":     "^0[0-7]{3}$",
				"default":     "0644",
			},
			"create_backup": map[string]interface{}{
				"type":        "boolean",
				"description": "Whether to create a backup before overwriting",
				"default":     true,
			},
			"force_overwrite": map[string]interface{}{
				"type":        "boolean",
				"description": "Whether to force overwrite of existing files",
				"default":     false,
			},
			"validate_checksum": map[string]interface{}{
				"type":        "boolean",
				"description": "Whether to validate content checksum after write",
				"default":     true,
			},
		},
		"required":             []string{"sandbox_id", "path", "content"},
		"additionalProperties": false,
	}
}

// EnhancedFileReadSchema returns the enhanced schema for file read operations
func EnhancedFileReadSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
				"pattern":     "^[a-zA-Z0-9-]+$",
			},
			"path": map[string]interface{}{
				"type":        "string",
				"description": "The file path to read",
				"pattern":     "^/.*",
				"maxLength":   1024,
			},
			"encoding": map[string]interface{}{
				"type":        "string",
				"description": "Content encoding (base64 or utf8)",
				"enum":        []string{"base64", "utf8"},
				"default":     "utf8",
			},
			"max_size": map[string]interface{}{
				"type":        "integer",
				"description": "Maximum file size to read in bytes",
				"minimum":     1,
				"maximum":     104857600, // 100MB
				"default":     1048576,   // 1MB
			},
			"offset": map[string]interface{}{
				"type":        "integer",
				"description": "Byte offset to start reading from",
				"minimum":     0,
				"default":     0,
			},
			"length": map[string]interface{}{
				"type":        "integer",
				"description": "Number of bytes to read (0 for all)",
				"minimum":     0,
				"default":     0,
			},
			"validate_checksum": map[string]interface{}{
				"type":        "boolean",
				"description": "Whether to include content checksum in response",
				"default":     true,
			},
		},
		"required":             []string{"sandbox_id", "path"},
		"additionalProperties": false,
	}
}

// EnhancedFileListSchema returns the enhanced schema for file listing operations
func EnhancedFileListSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
				"pattern":     "^[a-zA-Z0-9-]+$",
			},
			"path": map[string]interface{}{
				"type":        "string",
				"description": "Directory path to list (defaults to /workspace)",
				"pattern":     "^/.*",
				"default":     "/workspace",
				"maxLength":   1024,
			},
			"recursive": map[string]interface{}{
				"type":        "boolean",
				"description": "List files recursively",
				"default":     false,
			},
			"include_hidden": map[string]interface{}{
				"type":        "boolean",
				"description": "Include hidden files (starting with .)",
				"default":     false,
			},
			"include_metadata": map[string]interface{}{
				"type":        "boolean",
				"description": "Include detailed file metadata",
				"default":     true,
			},
			"sort_by": map[string]interface{}{
				"type":        "string",
				"description": "Sort files by specified field",
				"enum":        []string{"name", "size", "modified", "type"},
				"default":     "name",
			},
			"sort_order": map[string]interface{}{
				"type":        "string",
				"description": "Sort order",
				"enum":        []string{"asc", "desc"},
				"default":     "asc",
			},
			"filter_pattern": map[string]interface{}{
				"type":        "string",
				"description": "Glob pattern to filter files",
				"maxLength":   256,
			},
			"max_entries": map[string]interface{}{
				"type":        "integer",
				"description": "Maximum number of entries to return",
				"minimum":     1,
				"maximum":     10000,
				"default":     1000,
			},
		},
		"required":             []string{"sandbox_id"},
		"additionalProperties": false,
	}
}
