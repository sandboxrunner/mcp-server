package sandbox

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// initializeBuiltinTemplates initializes the built-in project templates
func (wm *WorkspaceManager) initializeBuiltinTemplates() {
	wm.templates["python-basic"] = &ProjectTemplate{
		ID:          "python-basic",
		Name:        "Python Basic Project",
		Description: "Basic Python project structure with common directories and files",
		Type:        WorkspaceTypePython,
		Structure: []TemplateItem{
			{Type: "directory", Path: "src", Permissions: "0755"},
			{Type: "directory", Path: "tests", Permissions: "0755"},
			{Type: "directory", Path: "docs", Permissions: "0755"},
			{Type: "file", Path: "main.py", Content: pythonMainTemplate, Variables: true, Permissions: "0644"},
			{Type: "file", Path: "requirements.txt", Content: "# Add your dependencies here\n", Permissions: "0644"},
			{Type: "file", Path: ".gitignore", Content: pythonGitignoreTemplate, Permissions: "0644"},
			{Type: "file", Path: "setup.py", Content: pythonSetupTemplate, Variables: true, Permissions: "0644"},
			{Type: "file", Path: "tests/test_main.py", Content: pythonTestTemplate, Variables: true, Permissions: "0644"},
		},
		Commands: []TemplateCommand{
			{
				Name:    "init-git",
				Command: "git",
				Args:    []string{"init"},
				Timeout: 10 * time.Second,
			},
		},
		Variables: map[string]string{
			"PROJECT_NAME": "My Python Project",
			"AUTHOR":       "Developer",
			"VERSION":      "0.1.0",
		},
		Version: "1.0.0",
	}

	wm.templates["nodejs-basic"] = &ProjectTemplate{
		ID:          "nodejs-basic",
		Name:        "Node.js Basic Project",
		Description: "Basic Node.js project with Express and common structure",
		Type:        WorkspaceTypeNodeJS,
		Structure: []TemplateItem{
			{Type: "directory", Path: "src", Permissions: "0755"},
			{Type: "directory", Path: "tests", Permissions: "0755"},
			{Type: "directory", Path: "public", Permissions: "0755"},
			{Type: "file", Path: "package.json", Content: nodejsPackageTemplate, Variables: true, Permissions: "0644"},
			{Type: "file", Path: "src/index.js", Content: nodejsIndexTemplate, Variables: true, Permissions: "0644"},
			{Type: "file", Path: ".gitignore", Content: nodejsGitignoreTemplate, Permissions: "0644"},
			{Type: "file", Path: "README.md", Content: nodejsReadmeTemplate, Variables: true, Permissions: "0644"},
		},
		Commands: []TemplateCommand{
			{
				Name:    "init-git",
				Command: "git",
				Args:    []string{"init"},
				Timeout: 10 * time.Second,
			},
			{
				Name:        "npm-install",
				Command:     "npm",
				Args:        []string{"install"},
				WorkingDir:  ".",
				Timeout:     120 * time.Second,
				RunCondition: "has_package_json",
			},
		},
		Variables: map[string]string{
			"PROJECT_NAME": "my-node-project",
			"DESCRIPTION":  "A Node.js project",
			"AUTHOR":       "Developer",
			"VERSION":      "1.0.0",
		},
		Version: "1.0.0",
	}

	wm.templates["go-basic"] = &ProjectTemplate{
		ID:          "go-basic",
		Name:        "Go Basic Project",
		Description: "Basic Go project with module structure",
		Type:        WorkspaceTypeGo,
		Structure: []TemplateItem{
			{Type: "directory", Path: "cmd", Permissions: "0755"},
			{Type: "directory", Path: "internal", Permissions: "0755"},
			{Type: "directory", Path: "pkg", Permissions: "0755"},
			{Type: "directory", Path: "test", Permissions: "0755"},
			{Type: "file", Path: "go.mod", Content: goModTemplate, Variables: true, Permissions: "0644"},
			{Type: "file", Path: "main.go", Content: goMainTemplate, Variables: true, Permissions: "0644"},
			{Type: "file", Path: ".gitignore", Content: goGitignoreTemplate, Permissions: "0644"},
			{Type: "file", Path: "Makefile", Content: goMakefileTemplate, Variables: true, Permissions: "0644"},
		},
		Commands: []TemplateCommand{
			{
				Name:    "init-git",
				Command: "git",
				Args:    []string{"init"},
				Timeout: 10 * time.Second,
			},
			{
				Name:    "go-mod-tidy",
				Command: "go",
				Args:    []string{"mod", "tidy"},
				Timeout: 60 * time.Second,
			},
		},
		Variables: map[string]string{
			"MODULE_NAME":  "example.com/my-go-project",
			"PROJECT_NAME": "my-go-project",
			"AUTHOR":       "Developer",
			"VERSION":      "v0.1.0",
		},
		Version: "1.0.0",
	}

	wm.templates["web-frontend"] = &ProjectTemplate{
		ID:          "web-frontend",
		Name:        "Web Frontend Project",
		Description: "Modern web frontend project with HTML, CSS, and JavaScript",
		Type:        WorkspaceTypeWeb,
		Structure: []TemplateItem{
			{Type: "directory", Path: "src", Permissions: "0755"},
			{Type: "directory", Path: "css", Permissions: "0755"},
			{Type: "directory", Path: "js", Permissions: "0755"},
			{Type: "directory", Path: "assets", Permissions: "0755"},
			{Type: "directory", Path: "assets/images", Permissions: "0755"},
			{Type: "file", Path: "index.html", Content: htmlIndexTemplate, Variables: true, Permissions: "0644"},
			{Type: "file", Path: "css/style.css", Content: cssStyleTemplate, Variables: true, Permissions: "0644"},
			{Type: "file", Path: "js/main.js", Content: jsMainTemplate, Variables: true, Permissions: "0644"},
			{Type: "file", Path: ".gitignore", Content: webGitignoreTemplate, Permissions: "0644"},
		},
		Commands: []TemplateCommand{
			{
				Name:    "init-git",
				Command: "git",
				Args:    []string{"init"},
				Timeout: 10 * time.Second,
			},
		},
		Variables: map[string]string{
			"PROJECT_NAME": "My Web Project",
			"AUTHOR":       "Developer",
			"DESCRIPTION":  "A modern web project",
		},
		Version: "1.0.0",
	}

	log.Info().Int("template_count", len(wm.templates)).Msg("Built-in templates initialized")
}

// applyTemplate applies a project template to a workspace
func (wm *WorkspaceManager) applyTemplate(ctx context.Context, workspace *Workspace, templateID string, variables map[string]string) error {
	template, exists := wm.templates[templateID]
	if !exists {
		return fmt.Errorf("template not found: %s", templateID)
	}

	log.Info().
		Str("workspace_id", workspace.ID).
		Str("template_id", templateID).
		Str("template_name", template.Name).
		Msg("Applying project template")

	// Merge template variables with provided variables
	allVars := make(map[string]string)
	for k, v := range template.Variables {
		allVars[k] = v
	}
	for k, v := range variables {
		allVars[k] = v
	}

	// Apply template structure
	for _, item := range template.Structure {
		itemPath := path.Join(workspace.RootPath, item.Path)
		
		switch item.Type {
		case "directory":
			if err := wm.containerFS.MakeDir(ctx, workspace.ContainerID, itemPath, 0755); err != nil {
				log.Warn().Err(err).Str("path", itemPath).Msg("Failed to create template directory")
			}

		case "file":
			content := item.Content
			if item.Variables {
				content = wm.processTemplateVariables(content, allVars)
			}
			
			if err := wm.containerFS.WriteFile(ctx, workspace.ContainerID, itemPath, []byte(content), 0644); err != nil {
				log.Warn().Err(err).Str("path", itemPath).Msg("Failed to create template file")
			}

		case "symlink":
			// Note: Symlink creation would need to be implemented in containerFS
			log.Debug().Str("path", itemPath).Str("target", item.Target).Msg("Symlink creation not yet implemented")
		}
	}

	// Execute template commands
	for _, cmd := range template.Commands {
		if err := wm.executeTemplateCommand(ctx, workspace, cmd, allVars); err != nil {
			log.Warn().Err(err).Str("command", cmd.Name).Msg("Failed to execute template command")
		}
	}

	workspace.Metadata["template_applied"] = templateID
	workspace.Metadata["template_version"] = template.Version
	workspace.Metadata["template_vars"] = allVars

	return nil
}

// executeTemplateCommand executes a template command in the workspace
func (wm *WorkspaceManager) executeTemplateCommand(ctx context.Context, workspace *Workspace, cmd TemplateCommand, variables map[string]string) error {
	// Process command and args with variables
	command := wm.processTemplateVariables(cmd.Command, variables)
	args := make([]string, len(cmd.Args))
	for i, arg := range cmd.Args {
		args[i] = wm.processTemplateVariables(arg, variables)
	}

	// Set working directory
	workingDir := workspace.RootPath
	if cmd.WorkingDir != "" {
		workingDir = path.Join(workspace.RootPath, cmd.WorkingDir)
	}

	// Create process spec for command execution
	// Note: processSpec would be used for actual command execution with runtime client

	log.Debug().
		Str("workspace_id", workspace.ID).
		Str("command", command).
		Strs("args", args).
		Str("working_dir", workingDir).
		Msg("Executing template command")

	// Execute command using runtime client (would need access to it)
	// This is a placeholder - in practice, you'd need the runtime client
	log.Info().
		Str("command_name", cmd.Name).
		Str("command", command).
		Msg("Template command execution completed (placeholder)")

	return nil
}

// processTemplateVariables replaces variables in template strings
func (wm *WorkspaceManager) processTemplateVariables(template string, variables map[string]string) string {
	result := template
	for key, value := range variables {
		placeholder := fmt.Sprintf("{{%s}}", key)
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

// buildCommandEnvironment builds environment variables for command execution
func (wm *WorkspaceManager) buildCommandEnvironment(cmdEnv map[string]string, variables map[string]string) []string {
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=/root",
	}

	// Add command-specific environment variables
	for key, value := range cmdEnv {
		processedValue := wm.processTemplateVariables(value, variables)
		env = append(env, fmt.Sprintf("%s=%s", key, processedValue))
	}

	return env
}

// GetTemplate retrieves a template by ID
func (wm *WorkspaceManager) GetTemplate(templateID string) (*ProjectTemplate, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	template, exists := wm.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}

	return template, nil
}

// ListTemplates returns all available templates
func (wm *WorkspaceManager) ListTemplates(workspaceType WorkspaceType) ([]*ProjectTemplate, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	var templates []*ProjectTemplate
	for _, template := range wm.templates {
		if workspaceType == "" || template.Type == workspaceType {
			templates = append(templates, template)
		}
	}

	return templates, nil
}

// AddCustomTemplate adds a custom project template
func (wm *WorkspaceManager) AddCustomTemplate(template *ProjectTemplate) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if template.ID == "" {
		return fmt.Errorf("template ID cannot be empty")
	}

	wm.templates[template.ID] = template

	log.Info().
		Str("template_id", template.ID).
		Str("template_name", template.Name).
		Msg("Custom template added")

	return nil
}

// Template content constants
const pythonMainTemplate = `#!/usr/bin/env python3
"""
{{PROJECT_NAME}}

A Python project created from template.
Author: {{AUTHOR}}
Version: {{VERSION}}
"""


def main():
    """Main function."""
    print("Hello from {{PROJECT_NAME}}!")


if __name__ == "__main__":
    main()
`

const pythonSetupTemplate = `from setuptools import setup, find_packages

setup(
    name="{{PROJECT_NAME}}",
    version="{{VERSION}}",
    author="{{AUTHOR}}",
    description="A Python project",
    packages=find_packages(),
    python_requires=">=3.6",
    install_requires=[
        # Add your dependencies here
    ],
    entry_points={
        "console_scripts": [
            "{{PROJECT_NAME}}=main:main",
        ],
    },
)
`

const pythonTestTemplate = `import unittest
from main import main


class TestMain(unittest.TestCase):
    """Test cases for main module."""

    def test_main(self):
        """Test main function."""
        # Add your tests here
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
`

const pythonGitignoreTemplate = `# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
`

const nodejsPackageTemplate = `{
  "name": "{{PROJECT_NAME}}",
  "version": "{{VERSION}}",
  "description": "{{DESCRIPTION}}",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js",
    "test": "jest"
  },
  "author": "{{AUTHOR}}",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.0"
  },
  "devDependencies": {
    "nodemon": "^2.0.0",
    "jest": "^28.0.0"
  }
}
`

const nodejsIndexTemplate = `const express = require('express');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Routes
app.get('/', (req, res) => {
  res.json({ message: 'Hello from {{PROJECT_NAME}}!' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Start server
app.listen(port, () => {
  console.log('{{PROJECT_NAME}} server listening on port ' + port);
});

module.exports = app;
`

const nodejsReadmeTemplate = "# {{PROJECT_NAME}}\n\n{{DESCRIPTION}}\n\n## Getting Started\n\n### Prerequisites\n\n- Node.js (version 14 or higher)\n- npm or yarn\n\n### Installation\n\n1. Install dependencies:\n   ```bash\n   npm install\n   ```\n\n2. Start the development server:\n   ```bash\n   npm run dev\n   ```\n\n3. Open [http://localhost:3000](http://localhost:3000) in your browser.\n\n## Scripts\n\n- `npm start` - Start the production server\n- `npm run dev` - Start the development server with auto-reload\n- `npm test` - Run tests\n\n## Author\n\n{{AUTHOR}}\n\n## License\n\nMIT"

const nodejsGitignoreTemplate = `# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/

# Environment variables
.env
.env.local

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Build output
dist/
build/
`

const goModTemplate = `module {{MODULE_NAME}}

go 1.21

require (
    // Add your dependencies here
)
`

const goMainTemplate = `package main

import (
    "fmt"
    "log"
)

// Version of the application
const Version = "{{VERSION}}"

func main() {
    fmt.Printf("Welcome to {{PROJECT_NAME}} %s\n", Version)
    log.Println("Application started successfully")
    
    // Your application logic here
}
`

const goMakefileTemplate = ".PHONY: build clean test run\n\nBINARY_NAME={{PROJECT_NAME}}\nVERSION={{VERSION}}\n\nbuild:\n\tgo build -o bin/$(BINARY_NAME) -ldflags=\"-X main.Version=$(VERSION)\" .\n\nclean:\n\trm -f bin/$(BINARY_NAME)\n\ntest:\n\tgo test -v ./...\n\nrun: build\n\t./bin/$(BINARY_NAME)\n\ninstall:\n\tgo install -ldflags=\"-X main.Version=$(VERSION)\" .\n\nfmt:\n\tgo fmt ./...\n\nvet:\n\tgo vet ./...\n\nmod:\n\tgo mod tidy\n\tgo mod download"

const goGitignoreTemplate = `# Binaries for programs and plugins
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary, built with 'go test -c'
*.test

# Output of the go coverage tool
*.out

# Go workspace file
go.work

# Build output
bin/
dist/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Local environment
.env
.env.local
`

const htmlIndexTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{PROJECT_NAME}}</title>
    <meta name="description" content="{{DESCRIPTION}}">
    <meta name="author" content="{{AUTHOR}}">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <header>
        <h1>{{PROJECT_NAME}}</h1>
        <nav>
            <ul>
                <li><a href="#home">Home</a></li>
                <li><a href="#about">About</a></li>
                <li><a href="#contact">Contact</a></li>
            </ul>
        </nav>
    </header>

    <main>
        <section id="home">
            <h2>Welcome</h2>
            <p>{{DESCRIPTION}}</p>
        </section>

        <section id="about">
            <h2>About</h2>
            <p>This is a modern web project created from a template.</p>
        </section>

        <section id="contact">
            <h2>Contact</h2>
            <p>Created by: {{AUTHOR}}</p>
        </section>
    </main>

    <footer>
        <p>&copy; 2024 {{AUTHOR}}. All rights reserved.</p>
    </footer>

    <script src="js/main.js"></script>
</body>
</html>
`

const cssStyleTemplate = `/* {{PROJECT_NAME}} Styles */
/* Author: {{AUTHOR}} */

:root {
    --primary-color: #007bff;
    --secondary-color: #6c757d;
    --success-color: #28a745;
    --danger-color: #dc3545;
    --warning-color: #ffc107;
    --info-color: #17a2b8;
    --light-color: #f8f9fa;
    --dark-color: #343a40;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    line-height: 1.6;
    color: var(--dark-color);
    background-color: var(--light-color);
}

header {
    background-color: var(--primary-color);
    color: white;
    padding: 1rem 0;
    position: sticky;
    top: 0;
    z-index: 1000;
}

header h1 {
    text-align: center;
    margin-bottom: 0.5rem;
}

nav ul {
    list-style: none;
    display: flex;
    justify-content: center;
    gap: 2rem;
}

nav a {
    color: white;
    text-decoration: none;
    padding: 0.5rem 1rem;
    border-radius: 4px;
    transition: background-color 0.3s;
}

nav a:hover {
    background-color: rgba(255, 255, 255, 0.2);
}

main {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
}

section {
    margin-bottom: 3rem;
    padding: 2rem;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

h2 {
    color: var(--primary-color);
    margin-bottom: 1rem;
}

footer {
    text-align: center;
    padding: 2rem;
    background-color: var(--dark-color);
    color: white;
    margin-top: 2rem;
}

@media (max-width: 768px) {
    nav ul {
        flex-direction: column;
        gap: 0.5rem;
    }
    
    main {
        padding: 1rem;
    }
    
    section {
        padding: 1rem;
    }
}
`

const jsMainTemplate = `// {{PROJECT_NAME}} JavaScript
// Author: {{AUTHOR}}

document.addEventListener('DOMContentLoaded', function() {
    console.log('{{PROJECT_NAME}} loaded successfully');
    
    // Initialize application
    init();
});

function init() {
    // Setup navigation
    setupNavigation();
    
    // Setup smooth scrolling
    setupSmoothScrolling();
    
    // Add interactive features
    addInteractivity();
}

function setupNavigation() {
    const navLinks = document.querySelectorAll('nav a[href^="#"]');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

function setupSmoothScrolling() {
    // Enable smooth scrolling for all anchor links
    const style = document.createElement('style');
    style.textContent = 'html { scroll-behavior: smooth; }';
    document.head.appendChild(style);
}

function addInteractivity() {
    // Add some interactive elements
    const sections = document.querySelectorAll('section');
    
    sections.forEach(section => {
        section.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px)';
            this.style.transition = 'transform 0.3s ease';
        });
        
        section.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
}

// Utility functions
function showMessage(message, type = 'info') {
    console.log('[' + type.toUpperCase() + '] ' + message);
}

function getCurrentTimestamp() {
    return new Date().toISOString();
}

// Export functions if using modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        init,
        showMessage,
        getCurrentTimestamp
    };
}
`

const webGitignoreTemplate = `# Dependencies
node_modules/

# Build output
dist/
build/
*.min.js
*.min.css

# Environment files
.env
.env.local
.env.production

# IDE files
.vscode/
.idea/
*.swp
*.swo

# OS files
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Cache
.cache/
.parcel-cache/

# Coverage reports
coverage/
`