package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
)

func main() {
	// Create a sandbox client with default configuration
	config := sandbox.DefaultConfig()
	client, err := sandbox.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create sandbox client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Create a basic sandbox
	fmt.Println("Creating sandbox...")
	sb, err := client.CreateBasicSandbox(ctx, "/workspace")
	if err != nil {
		log.Fatalf("Failed to create sandbox: %v", err)
	}

	fmt.Printf("Sandbox created: %s\n", sb.ID)

	// Write a file to the sandbox
	fmt.Println("Writing file to sandbox...")
	if err := client.WriteFile(ctx, sb.ID, "/workspace/hello.txt", "Hello, World!"); err != nil {
		log.Printf("Failed to write file: %v", err)
	} else {
		fmt.Println("File written successfully")
	}

	// Read the file back
	fmt.Println("Reading file from sandbox...")
	content, err := client.ReadFile(ctx, sb.ID, "/workspace/hello.txt")
	if err != nil {
		log.Printf("Failed to read file: %v", err)
	} else {
		fmt.Printf("File content: %s\n", content)
	}

	// List files in the workspace
	fmt.Println("Listing files in workspace...")
	files, err := client.ListFiles(ctx, sb.ID, "/workspace")
	if err != nil {
		log.Printf("Failed to list files: %v", err)
	} else {
		for _, file := range files {
			fmt.Printf("  %s (%d bytes, %s)\n", file.Name, file.Size, file.ModTime.Format(time.RFC3339))
		}
	}

	// Execute a command in the sandbox
	fmt.Println("Executing command in sandbox...")
	response, err := client.RunCommand(ctx, sb.ID, []string{"ls", "-la", "/workspace"}, 30*time.Second)
	if err != nil {
		log.Printf("Failed to execute command: %v", err)
	} else {
		fmt.Printf("Command output:\n%s\n", response.Stdout)
		if response.Stderr != "" {
			fmt.Printf("Command stderr:\n%s\n", response.Stderr)
		}
	}

	// Execute a more complex command
	fmt.Println("Creating and running a script...")
	script := `#!/bin/bash
echo "Current directory: $(pwd)"
echo "Files in directory:"
ls -la
echo "Environment variables:"
printenv | grep -E '^(PATH|HOME|PWD)' | sort
echo "Process info:"
ps aux | head -5
`

	if err := client.WriteFile(ctx, sb.ID, "/workspace/script.sh", script); err != nil {
		log.Printf("Failed to write script: %v", err)
	} else {
		// Make script executable and run it
		_, err := client.RunCommand(ctx, sb.ID, []string{"chmod", "+x", "/workspace/script.sh"}, 10*time.Second)
		if err != nil {
			log.Printf("Failed to make script executable: %v", err)
		} else {
			response, err := client.RunCommand(ctx, sb.ID, []string{"/workspace/script.sh"}, 30*time.Second)
			if err != nil {
				log.Printf("Failed to execute script: %v", err)
			} else {
				fmt.Printf("Script output:\n%s\n", response.Stdout)
			}
		}
	}

	// Search for files containing "Hello"
	fmt.Println("Searching for files containing 'Hello'...")
	searchResults, err := client.FindInFiles(ctx, sb.ID, "/workspace", "Hello")
	if err != nil {
		log.Printf("Failed to search in files: %v", err)
	} else {
		for _, result := range searchResults {
			fmt.Printf("Found in %s (line %d): %s\n", result.File.Path, result.LineNum, result.Line)
		}
	}

	// Replace text in files
	fmt.Println("Replacing 'World' with 'Sandbox' in files...")
	replacements, err := client.ReplaceInFiles(ctx, sb.ID, "/workspace", "World", "Sandbox")
	if err != nil {
		log.Printf("Failed to replace in files: %v", err)
	} else {
		fmt.Printf("Made %d replacements\n", replacements)

		// Read the file again to see the change
		content, err := client.ReadFile(ctx, sb.ID, "/workspace/hello.txt")
		if err != nil {
			log.Printf("Failed to read file after replacement: %v", err)
		} else {
			fmt.Printf("Updated file content: %s\n", content)
		}
	}

	// Get system metrics
	fmt.Println("Getting system metrics...")
	metrics, err := client.GetSystemMetrics()
	if err != nil {
		log.Printf("Failed to get metrics: %v", err)
	} else {
		fmt.Printf("Active sandboxes: %d\n", metrics.ActiveSandboxes)
		fmt.Printf("Running processes: %d\n", metrics.RunningProcesses)
	}

	// Get health status
	fmt.Println("Getting health status...")
	health, err := client.Health()
	if err != nil {
		log.Printf("Failed to get health: %v", err)
	} else {
		fmt.Printf("Health status: %s\n", health.Status)
		fmt.Printf("Uptime: %s\n", health.Uptime)
	}

	// Clean up - stop and delete the sandbox
	fmt.Println("Cleaning up...")
	if err := client.StopSandbox(ctx, sb.ID); err != nil {
		log.Printf("Failed to stop sandbox: %v", err)
	} else {
		fmt.Println("Sandbox stopped")
	}

	if err := client.DeleteSandbox(ctx, sb.ID); err != nil {
		log.Printf("Failed to delete sandbox: %v", err)
	} else {
		fmt.Println("Sandbox deleted")
	}

	fmt.Println("Example completed successfully!")
}

// Helper function to handle errors gracefully
func handleError(err error, message string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %v\n", message, err)
	}
}