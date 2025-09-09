package languages

import (
	"fmt"
	"strings"
)

// ImageConfig represents a container image configuration
type ImageConfig struct {
	Name        string            `json:"name"`
	Tag         string            `json:"tag"`
	Language    Language          `json:"language"`
	Description string            `json:"description"`
	Languages   []Language        `json:"languages"`   // For multi-language images
	Environment map[string]string `json:"environment"` // Default environment variables
	WorkingDir  string            `json:"working_dir"`
	User        string            `json:"user"`
	Entrypoint  []string          `json:"entrypoint"`
	Packages    []string          `json:"packages"` // Pre-installed packages
	Size        string            `json:"size"`
	Verified    bool              `json:"verified"`
}

// GetFullImageName returns the complete image name with tag
func (ic *ImageConfig) GetFullImageName() string {
	if ic.Tag == "" {
		return ic.Name
	}
	return fmt.Sprintf("%s:%s", ic.Name, ic.Tag)
}

// ImageRegistry manages container images for different languages
type ImageRegistry struct {
	images         map[Language][]ImageConfig
	defaultImages  map[Language]string
	polyglotImages []ImageConfig
}

// NewImageRegistry creates a new image registry
func NewImageRegistry() *ImageRegistry {
	registry := &ImageRegistry{
		images:        make(map[Language][]ImageConfig),
		defaultImages: make(map[Language]string),
	}

	registry.initializeImages()
	registry.initializePolyglotImages()

	return registry
}

// GetDefaultImage returns the default image for a language
func (ir *ImageRegistry) GetDefaultImage(language Language) string {
	if image, exists := ir.defaultImages[language]; exists {
		return image
	}
	return "ubuntu:22.04" // Fallback
}

// GetImages returns all images for a language
func (ir *ImageRegistry) GetImages(language Language) []ImageConfig {
	return ir.images[language]
}

// GetPolyglotImages returns images that support multiple languages
func (ir *ImageRegistry) GetPolyglotImages() []ImageConfig {
	return ir.polyglotImages
}

// FindImage finds a specific image by name and tag
func (ir *ImageRegistry) FindImage(name, tag string) *ImageConfig {
	for _, images := range ir.images {
		for _, img := range images {
			if img.Name == name && (tag == "" || img.Tag == tag) {
				return &img
			}
		}
	}

	for _, img := range ir.polyglotImages {
		if img.Name == name && (tag == "" || img.Tag == tag) {
			return &img
		}
	}

	return nil
}

// GetBestImage returns the best image for given requirements
func (ir *ImageRegistry) GetBestImage(language Language, version string, packages []string) *ImageConfig {
	images := ir.GetImages(language)
	if len(images) == 0 {
		// Try polyglot images
		for _, img := range ir.polyglotImages {
			for _, lang := range img.Languages {
				if lang == language {
					return &img
				}
			}
		}
		return nil
	}

	// Simple selection logic - can be enhanced
	for _, img := range images {
		if version == "" || strings.Contains(img.Tag, version) {
			return &img
		}
	}

	return &images[0] // Return first (usually default)
}

// initializeImages sets up language-specific images
func (ir *ImageRegistry) initializeImages() {
	// Python images
	ir.images[LanguagePython] = []ImageConfig{
		{
			Name:        "python",
			Tag:         "3.12-slim",
			Language:    LanguagePython,
			Description: "Official Python 3.12 slim image",
			Environment: map[string]string{
				"PYTHONUNBUFFERED":        "1",
				"PYTHONDONTWRITEBYTECODE": "1",
			},
			WorkingDir: "/workspace",
			User:       "root",
			Packages:   []string{"pip", "setuptools", "wheel"},
			Verified:   true,
		},
		{
			Name:        "python",
			Tag:         "3.11-slim",
			Language:    LanguagePython,
			Description: "Official Python 3.11 slim image",
			Environment: map[string]string{
				"PYTHONUNBUFFERED":        "1",
				"PYTHONDONTWRITEBYTECODE": "1",
			},
			WorkingDir: "/workspace",
			User:       "root",
			Packages:   []string{"pip", "setuptools", "wheel"},
			Verified:   true,
		},
		{
			Name:        "jupyter/scipy-notebook",
			Tag:         "latest",
			Language:    LanguagePython,
			Description: "Jupyter notebook with scientific packages",
			Environment: map[string]string{
				"JUPYTER_ENABLE_LAB": "yes",
			},
			WorkingDir: "/home/jovyan/work",
			User:       "jovyan",
			Packages:   []string{"numpy", "pandas", "scipy", "matplotlib", "jupyter"},
			Verified:   true,
		},
	}

	// JavaScript/Node.js images
	ir.images[LanguageJavaScript] = []ImageConfig{
		{
			Name:        "node",
			Tag:         "20-alpine",
			Language:    LanguageJavaScript,
			Description: "Official Node.js 20 Alpine image",
			Environment: map[string]string{
				"NODE_ENV": "development",
			},
			WorkingDir: "/workspace",
			User:       "node",
			Packages:   []string{"npm", "yarn"},
			Verified:   true,
		},
		{
			Name:        "node",
			Tag:         "18-alpine",
			Language:    LanguageJavaScript,
			Description: "Official Node.js 18 Alpine image",
			Environment: map[string]string{
				"NODE_ENV": "development",
			},
			WorkingDir: "/workspace",
			User:       "node",
			Packages:   []string{"npm", "yarn"},
			Verified:   true,
		},
	}

	// TypeScript images
	ir.images[LanguageTypeScript] = []ImageConfig{
		{
			Name:        "node",
			Tag:         "20-alpine",
			Language:    LanguageTypeScript,
			Description: "Node.js 20 with TypeScript support",
			Environment: map[string]string{
				"NODE_ENV": "development",
			},
			WorkingDir: "/workspace",
			User:       "node",
			Packages:   []string{"typescript", "@types/node", "ts-node"},
			Verified:   true,
		},
	}

	// Go images
	ir.images[LanguageGo] = []ImageConfig{
		{
			Name:        "golang",
			Tag:         "1.21-alpine",
			Language:    LanguageGo,
			Description: "Official Go 1.21 Alpine image",
			Environment: map[string]string{
				"GO111MODULE": "on",
				"CGO_ENABLED": "0",
			},
			WorkingDir: "/workspace",
			User:       "root",
			Packages:   []string{"go"},
			Verified:   true,
		},
		{
			Name:        "golang",
			Tag:         "1.20-alpine",
			Language:    LanguageGo,
			Description: "Official Go 1.20 Alpine image",
			Environment: map[string]string{
				"GO111MODULE": "on",
				"CGO_ENABLED": "0",
			},
			WorkingDir: "/workspace",
			User:       "root",
			Packages:   []string{"go"},
			Verified:   true,
		},
	}

	// Rust images
	ir.images[LanguageRust] = []ImageConfig{
		{
			Name:        "rust",
			Tag:         "1.75-slim",
			Language:    LanguageRust,
			Description: "Official Rust 1.75 slim image",
			Environment: map[string]string{
				"CARGO_HOME":  "/usr/local/cargo",
				"RUSTUP_HOME": "/usr/local/rustup",
			},
			WorkingDir: "/workspace",
			User:       "root",
			Packages:   []string{"cargo", "rustc"},
			Verified:   true,
		},
	}

	// Java images
	ir.images[LanguageJava] = []ImageConfig{
		{
			Name:        "openjdk",
			Tag:         "21-jdk-slim",
			Language:    LanguageJava,
			Description: "OpenJDK 21 slim image",
			Environment: map[string]string{
				"JAVA_HOME": "/usr/local/openjdk-21",
			},
			WorkingDir: "/workspace",
			User:       "root",
			Packages:   []string{"javac", "java", "maven"},
			Verified:   true,
		},
		{
			Name:        "openjdk",
			Tag:         "17-jdk-slim",
			Language:    LanguageJava,
			Description: "OpenJDK 17 slim image",
			Environment: map[string]string{
				"JAVA_HOME": "/usr/local/openjdk-17",
			},
			WorkingDir: "/workspace",
			User:       "root",
			Packages:   []string{"javac", "java", "maven"},
			Verified:   true,
		},
	}

	// C/C++ images
	ir.images[LanguageC] = []ImageConfig{
		{
			Name:        "gcc",
			Tag:         "latest",
			Language:    LanguageC,
			Description: "GCC compiler image",
			WorkingDir:  "/workspace",
			User:        "root",
			Packages:    []string{"gcc", "make", "gdb"},
			Verified:    true,
		},
	}

	ir.images[LanguageCPP] = []ImageConfig{
		{
			Name:        "gcc",
			Tag:         "latest",
			Language:    LanguageCPP,
			Description: "GCC compiler with C++ support",
			WorkingDir:  "/workspace",
			User:        "root",
			Packages:    []string{"g++", "make", "gdb"},
			Verified:    true,
		},
	}

	// C# images
	ir.images[LanguageCSharp] = []ImageConfig{
		{
			Name:        "mcr.microsoft.com/dotnet/sdk",
			Tag:         "8.0",
			Language:    LanguageCSharp,
			Description: "Official .NET 8 SDK image",
			Environment: map[string]string{
				"DOTNET_CLI_TELEMETRY_OPTOUT":       "1",
				"DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
				"DOTNET_NOLOGO":                     "1",
			},
			WorkingDir: "/workspace",
			User:       "root",
			Packages:   []string{"dotnet"},
			Verified:   true,
		},
		{
			Name:        "mcr.microsoft.com/dotnet/sdk",
			Tag:         "7.0",
			Language:    LanguageCSharp,
			Description: "Official .NET 7 SDK image",
			Environment: map[string]string{
				"DOTNET_CLI_TELEMETRY_OPTOUT":       "1",
				"DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
				"DOTNET_NOLOGO":                     "1",
			},
			WorkingDir: "/workspace",
			User:       "root",
			Packages:   []string{"dotnet"},
			Verified:   true,
		},
		{
			Name:        "mcr.microsoft.com/dotnet/sdk",
			Tag:         "6.0",
			Language:    LanguageCSharp,
			Description: "Official .NET 6 SDK image",
			Environment: map[string]string{
				"DOTNET_CLI_TELEMETRY_OPTOUT":       "1",
				"DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
				"DOTNET_NOLOGO":                     "1",
			},
			WorkingDir: "/workspace",
			User:       "root",
			Packages:   []string{"dotnet"},
			Verified:   true,
		},
	}

	// Ruby images
	ir.images[LanguageRuby] = []ImageConfig{
		{
			Name:        "ruby",
			Tag:         "3.3-alpine",
			Language:    LanguageRuby,
			Description: "Official Ruby 3.3 Alpine image",
			WorkingDir:  "/workspace",
			User:        "root",
			Packages:    []string{"gem", "bundler"},
			Verified:    true,
		},
	}

	// PHP images
	ir.images[LanguagePHP] = []ImageConfig{
		{
			Name:        "php",
			Tag:         "8.3-cli-alpine",
			Language:    LanguagePHP,
			Description: "Official PHP 8.3 CLI Alpine image",
			WorkingDir:  "/workspace",
			User:        "root",
			Packages:    []string{"composer"},
			Verified:    true,
		},
	}

	// Shell images
	ir.images[LanguageShell] = []ImageConfig{
		{
			Name:        "alpine",
			Tag:         "latest",
			Language:    LanguageShell,
			Description: "Alpine Linux with shell tools",
			WorkingDir:  "/workspace",
			User:        "root",
			Packages:    []string{"bash", "zsh", "fish", "curl", "wget", "jq"},
			Verified:    true,
		},
		{
			Name:        "ubuntu",
			Tag:         "22.04",
			Language:    LanguageShell,
			Description: "Ubuntu 22.04 with shell tools",
			WorkingDir:  "/workspace",
			User:        "root",
			Packages:    []string{"bash", "curl", "wget", "jq", "git"},
			Verified:    true,
		},
	}

	// R images
	ir.images[LanguageR] = []ImageConfig{
		{
			Name:        "r-base",
			Tag:         "latest",
			Language:    LanguageR,
			Description: "Official R base image",
			WorkingDir:  "/workspace",
			User:        "root",
			Packages:    []string{"r", "rscript"},
			Verified:    true,
		},
	}

	// Lua images
	ir.images[LanguageLua] = []ImageConfig{
		{
			Name:        "alpine",
			Tag:         "latest",
			Language:    LanguageLua,
			Description: "Alpine with Lua",
			WorkingDir:  "/workspace",
			User:        "root",
			Packages:    []string{"lua", "luarocks"},
			Verified:    true,
		},
	}

	// Perl images
	ir.images[LanguagePerl] = []ImageConfig{
		{
			Name:        "perl",
			Tag:         "slim",
			Language:    LanguagePerl,
			Description: "Official Perl slim image",
			WorkingDir:  "/workspace",
			User:        "root",
			Packages:    []string{"perl", "cpan"},
			Verified:    true,
		},
	}

	// Set default images
	ir.defaultImages[LanguagePython] = "python:3.12-slim"
	ir.defaultImages[LanguageJavaScript] = "node:20-alpine"
	ir.defaultImages[LanguageTypeScript] = "node:20-alpine"
	ir.defaultImages[LanguageGo] = "golang:1.21-alpine"
	ir.defaultImages[LanguageRust] = "rust:1.75-slim"
	ir.defaultImages[LanguageJava] = "openjdk:21-jdk-slim"
	ir.defaultImages[LanguageC] = "gcc:latest"
	ir.defaultImages[LanguageCPP] = "gcc:latest"
	ir.defaultImages[LanguageCSharp] = "mcr.microsoft.com/dotnet/sdk:8.0"
	ir.defaultImages[LanguageRuby] = "ruby:3.3-alpine"
	ir.defaultImages[LanguagePHP] = "php:8.3-cli-alpine"
	ir.defaultImages[LanguageShell] = "alpine:latest"
	ir.defaultImages[LanguageR] = "r-base:latest"
	ir.defaultImages[LanguageLua] = "alpine:latest"
	ir.defaultImages[LanguagePerl] = "perl:slim"
}

// initializePolyglotImages sets up multi-language images
func (ir *ImageRegistry) initializePolyglotImages() {
	ir.polyglotImages = []ImageConfig{
		{
			Name:        "jupyter/datascience-notebook",
			Tag:         "latest",
			Description: "Jupyter with Python, R, and Julia",
			Languages:   []Language{LanguagePython, LanguageR},
			Environment: map[string]string{
				"JUPYTER_ENABLE_LAB": "yes",
			},
			WorkingDir: "/home/jovyan/work",
			User:       "jovyan",
			Packages:   []string{"python", "r", "julia", "jupyter"},
			Verified:   true,
		},
		{
			Name:        "codeserver/code-server",
			Tag:         "latest",
			Description: "VS Code Server with multiple language support",
			Languages:   []Language{LanguagePython, LanguageJavaScript, LanguageTypeScript, LanguageGo},
			WorkingDir:  "/workspace",
			User:        "coder",
			Packages:    []string{"python", "node", "go", "typescript"},
			Verified:    true,
		},
		{
			Name:        "theiaide/theia-full",
			Tag:         "latest",
			Description: "Theia IDE with full language support",
			Languages: []Language{
				LanguagePython, LanguageJavaScript, LanguageTypeScript,
				LanguageJava, LanguageGo, LanguageRust, LanguageCPP,
			},
			WorkingDir: "/workspace",
			User:       "theia",
			Verified:   false,
		},
	}
}
