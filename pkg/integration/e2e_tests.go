package integration

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// TestEndToEndUserJourneys tests complete user workflows from start to finish
func TestEndToEndUserJourneys(t *testing.T) {
	framework := SetupTestFramework(t, DefaultTestEnvironment())
	asserts := NewIntegrationAsserts(t)
	dataGen := NewTestDataGenerator()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	t.Run("CompleteDataScienceWorkflow", func(t *testing.T) {
		// Journey: Data scientist creates a sandbox, uploads data, installs packages, runs analysis
		
		// Step 1: Create sandbox for data science work
		dataScienceContainer := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Environment: map[string]string{
				"PYTHONPATH":     "/workspace",
				"JUPYTER_CONFIG": "/workspace/.jupyter",
				"WORKFLOW_TYPE":  "data_science",
			},
			Resources: sandbox.ResourceLimits{
				CPULimit:    "2.0",
				MemoryLimit: "1G",
				DiskLimit:   "2G",
			},
		})

		framework.WaitForSandboxReady(ctx, t, dataScienceContainer.ID, 30*time.Second)
		
		// Step 2: Upload Python analysis script
		analysisScript := `#!/usr/bin/env python3
import sys
import json
import math

def analyze_data(data):
    """Simple data analysis function"""
    if not data:
        return {"error": "No data provided"}
    
    numbers = [float(x) for x in data if x.replace('.', '').replace('-', '').isdigit()]
    
    if not numbers:
        return {"error": "No numeric data found"}
    
    analysis = {
        "count": len(numbers),
        "sum": sum(numbers),
        "mean": sum(numbers) / len(numbers),
        "min": min(numbers),
        "max": max(numbers),
        "std_dev": math.sqrt(sum((x - sum(numbers)/len(numbers))**2 for x in numbers) / len(numbers))
    }
    
    return analysis

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze.py <data_file>")
        sys.exit(1)
    
    try:
        with open(sys.argv[1], 'r') as f:
            data = f.read().strip().split('\n')
        
        result = analyze_data(data)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
`

		uploadTool := &tools.UploadFileTool{Manager: framework.SandboxManager}
		_, err := uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id":  dataScienceContainer.ID,
			"file_path":   "/workspace/analyze.py",
			"content":     analysisScript,
			"permissions": "0755",
		})
		require.NoError(t, err)

		// Step 3: Upload test data
		testData := "10\n20\n30\n40\n50\n15.5\n25.7\n35.2"
		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": dataScienceContainer.ID,
			"file_path":  "/workspace/data.txt",
			"content":    testData,
		})
		require.NoError(t, err)

		// Step 4: Install required packages (simulate pip install)
		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
		result, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": dataScienceContainer.ID,
			"command":    "python3",
			"args":       []string{"-c", "import json, math; print('Dependencies available')"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		// Step 5: Run analysis
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": dataScienceContainer.ID,
			"command":    "python3",
			"args":       []string{"/workspace/analyze.py", "/workspace/data.txt"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		// Verify analysis results
		output := result.(*tools.ExecutionResult).Stdout
		assert.Contains(t, output, "count", "Analysis should include count")
		assert.Contains(t, output, "mean", "Analysis should include mean")
		assert.Contains(t, output, "std_dev", "Analysis should include standard deviation")

		// Step 6: Download results
		downloadTool := &tools.DownloadFileTool{Manager: framework.SandboxManager}
		downloadResult, err := downloadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": dataScienceContainer.ID,
			"file_path":  "/workspace/analyze.py",
		})
		require.NoError(t, err)
		
		downloadedContent := downloadResult.(map[string]interface{})["content"].(string)
		assert.Contains(t, downloadedContent, "def analyze_data", "Downloaded file should contain analysis function")

		t.Log("Data science workflow completed successfully")
	})

	t.Run("WebDevelopmentWorkflow", func(t *testing.T) {
		// Journey: Web developer creates a web application with frontend and backend
		
		// Step 1: Create sandbox for web development
		webDevContainer := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Environment: map[string]string{
				"NODE_ENV":      "development",
				"PORT":         "3000",
				"WORKFLOW_TYPE": "web_development",
			},
			Resources: sandbox.ResourceLimits{
				CPULimit:    "1.0",
				MemoryLimit: "512M",
				DiskLimit:   "1G",
			},
		})

		framework.WaitForSandboxReady(ctx, t, webDevContainer.ID, 30*time.Second)

		// Step 2: Create project structure
		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
		
		// Create directories
		result, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": webDevContainer.ID,
			"command":    "mkdir",
			"args":       []string{"-p", "/workspace/src", "/workspace/public", "/workspace/tests"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		// Step 3: Upload package.json
		packageJson := `{
  "name": "test-web-app",
  "version": "1.0.0",
  "description": "Test web application",
  "main": "src/app.js",
  "scripts": {
    "start": "node src/app.js",
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "dependencies": {
    "express": "^4.18.0"
  }
}`

		uploadTool := &tools.UploadFileTool{Manager: framework.SandboxManager}
		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": webDevContainer.ID,
			"file_path":  "/workspace/package.json",
			"content":    packageJson,
		})
		require.NoError(t, err)

		// Step 4: Create simple Express application
		appJs := `const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files
app.use(express.static('public'));

// Routes
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/api/hello/:name', (req, res) => {
    const name = req.params.name || 'World';
    res.json({ message: ` + "`Hello, ${name}!`" + `, timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
    res.send(` + "`" + `
        <html>
            <head><title>Test Web App</title></head>
            <body>
                <h1>Welcome to Test Web App</h1>
                <p>API endpoints:</p>
                <ul>
                    <li><a href="/api/health">/api/health</a></li>
                    <li><a href="/api/hello/Developer">/api/hello/Developer</a></li>
                </ul>
            </body>
        </html>
    ` + "`" + `);
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(` + "`Server running on port ${PORT}`" + `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('Received SIGTERM, shutting down gracefully');
    server.close(() => {
        process.exit(0);
    });
});

module.exports = app;
`

		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": webDevContainer.ID,
			"file_path":  "/workspace/src/app.js",
			"content":    appJs,
		})
		require.NoError(t, err)

		// Step 5: Create test file
		testJs := `const request = require('supertest');
const app = require('../src/app');

describe('API Tests', () => {
    test('Health endpoint', async () => {
        const response = await request(app).get('/api/health');
        expect(response.status).toBe(200);
        expect(response.body.status).toBe('healthy');
    });

    test('Hello endpoint', async () => {
        const response = await request(app).get('/api/hello/Test');
        expect(response.status).toBe(200);
        expect(response.body.message).toBe('Hello, Test!');
    });
});
`

		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": webDevContainer.ID,
			"file_path":  "/workspace/tests/app.test.js",
			"content":    testJs,
		})
		require.NoError(t, err)

		// Step 6: Verify file structure
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": webDevContainer.ID,
			"command":    "find",
			"args":       []string{"/workspace", "-type", "f", "-name", "*.js", "-o", "-name", "*.json"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		output := result.(*tools.ExecutionResult).Stdout
		assert.Contains(t, output, "package.json", "Should find package.json")
		assert.Contains(t, output, "src/app.js", "Should find app.js")
		assert.Contains(t, output, "tests/app.test.js", "Should find test file")

		// Step 7: Test application startup (without actual npm install, simulate check)
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": webDevContainer.ID,
			"command":    "node",
			"args":       []string{"-e", "console.log('Node.js is available'); process.exit(0);"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		t.Log("Web development workflow completed successfully")
	})

	t.Run("MLTrainingWorkflow", func(t *testing.T) {
		// Journey: ML engineer trains and validates a model
		
		// Step 1: Create ML training sandbox
		mlContainer := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Environment: map[string]string{
				"PYTHONPATH":    "/workspace",
				"MODEL_DIR":     "/workspace/models",
				"DATA_DIR":      "/workspace/data",
				"WORKFLOW_TYPE": "machine_learning",
			},
			Resources: sandbox.ResourceLimits{
				CPULimit:    "2.0",
				MemoryLimit: "2G",
				DiskLimit:   "5G",
			},
		})

		framework.WaitForSandboxReady(ctx, t, mlContainer.ID, 30*time.Second)

		// Step 2: Create directory structure
		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
		result, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": mlContainer.ID,
			"command":    "mkdir",
			"args":       []string{"-p", "/workspace/models", "/workspace/data", "/workspace/scripts", "/workspace/results"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		// Step 3: Upload training script
		trainingScript := `#!/usr/bin/env python3
import json
import random
import math
import sys
from datetime import datetime

class SimpleLinearModel:
    def __init__(self):
        self.weights = None
        self.bias = None
        self.trained = False
    
    def train(self, X, y, epochs=100, lr=0.01):
        """Simple linear regression training"""
        if not X or not y or len(X) != len(y):
            raise ValueError("Invalid training data")
        
        # Initialize parameters
        self.weights = [random.uniform(-1, 1) for _ in range(len(X[0]))]
        self.bias = random.uniform(-1, 1)
        
        # Training loop
        for epoch in range(epochs):
            total_loss = 0
            for i in range(len(X)):
                # Forward pass
                prediction = sum(self.weights[j] * X[i][j] for j in range(len(X[i]))) + self.bias
                loss = (prediction - y[i]) ** 2
                total_loss += loss
                
                # Backward pass (simplified)
                error = prediction - y[i]
                for j in range(len(X[i])):
                    self.weights[j] -= lr * error * X[i][j]
                self.bias -= lr * error
            
            if epoch % 20 == 0:
                avg_loss = total_loss / len(X)
                print(f"Epoch {epoch}: Loss = {avg_loss:.4f}")
        
        self.trained = True
        return {"epochs": epochs, "final_loss": total_loss / len(X)}
    
    def predict(self, X):
        if not self.trained:
            raise ValueError("Model not trained")
        
        predictions = []
        for x in X:
            pred = sum(self.weights[j] * x[j] for j in range(len(x))) + self.bias
            predictions.append(pred)
        return predictions
    
    def save(self, filepath):
        model_data = {
            "weights": self.weights,
            "bias": self.bias,
            "trained": self.trained,
            "timestamp": datetime.now().isoformat()
        }
        with open(filepath, 'w') as f:
            json.dump(model_data, f, indent=2)

def generate_synthetic_data(n_samples=100):
    """Generate synthetic training data"""
    X = []
    y = []
    
    for _ in range(n_samples):
        # Two features
        x1 = random.uniform(-10, 10)
        x2 = random.uniform(-10, 10)
        
        # Linear relationship with noise
        target = 2 * x1 + 3 * x2 + random.uniform(-1, 1)
        
        X.append([x1, x2])
        y.append(target)
    
    return X, y

def main():
    print("Starting ML training workflow...")
    
    # Generate synthetic data
    print("Generating synthetic data...")
    X_train, y_train = generate_synthetic_data(200)
    X_test, y_test = generate_synthetic_data(50)
    
    # Train model
    print("Training model...")
    model = SimpleLinearModel()
    training_result = model.train(X_train, y_train, epochs=100)
    
    # Evaluate model
    print("Evaluating model...")
    predictions = model.predict(X_test)
    mse = sum((pred - actual) ** 2 for pred, actual in zip(predictions, y_test)) / len(y_test)
    
    # Save model
    model_path = "/workspace/models/trained_model.json"
    model.save(model_path)
    
    # Save results
    results = {
        "training": training_result,
        "evaluation": {
            "mse": mse,
            "rmse": math.sqrt(mse),
            "test_samples": len(y_test)
        },
        "model_path": model_path,
        "timestamp": datetime.now().isoformat()
    }
    
    with open("/workspace/results/training_results.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Training completed. MSE: {mse:.4f}, RMSE: {math.sqrt(mse):.4f}")
    print(f"Model saved to: {model_path}")
    print(f"Results saved to: /workspace/results/training_results.json")

if __name__ == "__main__":
    main()
`

		uploadTool := &tools.UploadFileTool{Manager: framework.SandboxManager}
		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id":  mlContainer.ID,
			"file_path":   "/workspace/scripts/train_model.py",
			"content":     trainingScript,
			"permissions": "0755",
		})
		require.NoError(t, err)

		// Step 4: Run training
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": mlContainer.ID,
			"command":    "python3",
			"args":       []string{"/workspace/scripts/train_model.py"},
			"timeout":    120, // Allow 2 minutes for training
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		output := result.(*tools.ExecutionResult).Stdout
		assert.Contains(t, output, "Training completed", "Training should complete successfully")
		assert.Contains(t, output, "MSE:", "Should report MSE metric")
		assert.Contains(t, output, "Model saved to:", "Should save model")

		// Step 5: Verify model files exist
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": mlContainer.ID,
			"command":    "ls",
			"args":       []string{"-la", "/workspace/models/", "/workspace/results/"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		output = result.(*tools.ExecutionResult).Stdout
		assert.Contains(t, output, "trained_model.json", "Model file should exist")
		assert.Contains(t, output, "training_results.json", "Results file should exist")

		// Step 6: Download and verify results
		downloadTool := &tools.DownloadFileTool{Manager: framework.SandboxManager}
		downloadResult, err := downloadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": mlContainer.ID,
			"file_path":  "/workspace/results/training_results.json",
		})
		require.NoError(t, err)

		resultsContent := downloadResult.(map[string]interface{})["content"].(string)
		assert.Contains(t, resultsContent, "training", "Results should contain training section")
		assert.Contains(t, resultsContent, "evaluation", "Results should contain evaluation section")
		assert.Contains(t, resultsContent, "mse", "Results should contain MSE")

		t.Log("ML training workflow completed successfully")
	})

	t.Run("CrossLanguageDevelopmentWorkflow", func(t *testing.T) {
		// Journey: Developer works with multiple programming languages in one project
		
		// Step 1: Create multi-language development sandbox
		multiLangContainer := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Environment: map[string]string{
				"GOPATH":        "/workspace/go",
				"PYTHONPATH":    "/workspace/python",
				"NODE_PATH":     "/workspace/node",
				"WORKFLOW_TYPE": "multi_language",
			},
			Resources: sandbox.ResourceLimits{
				CPULimit:    "2.0",
				MemoryLimit: "1G",
				DiskLimit:   "2G",
			},
		})

		framework.WaitForSandboxReady(ctx, t, multiLangContainer.ID, 30*time.Second)

		// Step 2: Create language-specific directories
		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
		result, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": multiLangContainer.ID,
			"command":    "mkdir",
			"args":       []string{"-p", "/workspace/go/src", "/workspace/python", "/workspace/node", "/workspace/rust/src", "/workspace/shared"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		// Step 3: Create Python microservice
		pythonService, pythonContent := dataGen.GenerateCodeSample("python")
		uploadTool := &tools.UploadFileTool{Manager: framework.SandboxManager}
		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id":  multiLangContainer.ID,
			"file_path":   filepath.Join("/workspace/python", pythonService),
			"content":     pythonContent,
			"permissions": "0755",
		})
		require.NoError(t, err)

		// Step 4: Create Go microservice
		goService, goContent := dataGen.GenerateCodeSample("go")
		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": multiLangContainer.ID,
			"file_path":  filepath.Join("/workspace/go/src", goService),
			"content":    goContent,
		})
		require.NoError(t, err)

		// Step 5: Create Node.js microservice
		nodeService, nodeContent := dataGen.GenerateCodeSample("javascript")
		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id":  multiLangContainer.ID,
			"file_path":   filepath.Join("/workspace/node", nodeService),
			"content":     nodeContent,
			"permissions": "0755",
		})
		require.NoError(t, err)

		// Step 6: Create Rust microservice
		rustService, rustContent := dataGen.GenerateCodeSample("rust")
		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": multiLangContainer.ID,
			"file_path":  filepath.Join("/workspace/rust/src", rustService),
			"content":    rustContent,
		})
		require.NoError(t, err)

		// Step 7: Test Python execution
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": multiLangContainer.ID,
			"command":    "python3",
			"args":       []string{filepath.Join("/workspace/python", pythonService), "test_arg"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))
		assert.Contains(t, result.(*tools.ExecutionResult).Stdout, "Hello from Python", "Python service should execute")

		// Step 8: Test Node.js execution
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": multiLangContainer.ID,
			"command":    "node",
			"args":       []string{filepath.Join("/workspace/node", nodeService), "test_arg"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))
		assert.Contains(t, result.(*tools.ExecutionResult).Stdout, "Hello from Node.js", "Node.js service should execute")

		// Step 9: Test availability of different runtime environments
		languages := []struct {
			name    string
			command string
			args    []string
		}{
			{"Python", "python3", []string{"--version"}},
			{"Node.js", "node", []string{"--version"}},
			{"Go", "go", []string{"version"}},
		}

		for _, lang := range languages {
			result, err = execTool.Execute(ctx, map[string]interface{}{
				"sandbox_id": multiLangContainer.ID,
				"command":    lang.command,
				"args":       lang.args,
			})
			// Note: Some commands might not be available in basic Ubuntu image
			// In a real implementation, you'd use specialized images
			if err == nil && result.(*tools.ExecutionResult).ExitCode == 0 {
				t.Logf("%s is available: %s", lang.name, strings.TrimSpace(result.(*tools.ExecutionResult).Stdout))
			} else {
				t.Logf("%s runtime not available (expected in basic image)", lang.name)
			}
		}

		// Step 10: Create shared configuration file
		sharedConfig := `{
  "project": "multi-language-microservices",
  "version": "1.0.0",
  "services": {
    "python": {
      "port": 5000,
      "path": "/workspace/python/test.py"
    },
    "node": {
      "port": 3000,
      "path": "/workspace/node/test.js"
    },
    "go": {
      "port": 8080,
      "path": "/workspace/go/src/main.go"
    },
    "rust": {
      "port": 8081,
      "path": "/workspace/rust/src/main.rs"
    }
  }
}`

		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": multiLangContainer.ID,
			"file_path":  "/workspace/shared/config.json",
			"content":    sharedConfig,
		})
		require.NoError(t, err)

		// Step 11: Verify project structure
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": multiLangContainer.ID,
			"command":    "find",
			"args":       []string{"/workspace", "-name", "*.py", "-o", "-name", "*.js", "-o", "-name", "*.go", "-o", "-name", "*.rs", "-o", "-name", "*.json"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		output := result.(*tools.ExecutionResult).Stdout
		assert.Contains(t, output, "test.py", "Should find Python file")
		assert.Contains(t, output, "test.js", "Should find JavaScript file")
		assert.Contains(t, output, "main.go", "Should find Go file")
		assert.Contains(t, output, "main.rs", "Should find Rust file")
		assert.Contains(t, output, "config.json", "Should find shared config")

		t.Log("Cross-language development workflow completed successfully")
	})

	t.Run("CI/CDPipelineSimulation", func(t *testing.T) {
		// Journey: Developer sets up and runs a CI/CD pipeline
		
		// Step 1: Create CI/CD sandbox
		cicdContainer := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Environment: map[string]string{
				"CI":            "true",
				"BUILD_NUMBER":  "123",
				"GIT_BRANCH":    "main",
				"WORKFLOW_TYPE": "ci_cd",
			},
		})

		framework.WaitForSandboxReady(ctx, t, cicdContainer.ID, 30*time.Second)

		// Step 2: Create project structure
		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
		result, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": cicdContainer.ID,
			"command":    "mkdir",
			"args":       []string{"-p", "/workspace/src", "/workspace/tests", "/workspace/build", "/workspace/.github/workflows"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		// Step 3: Create CI pipeline script
		ciScript := `#!/bin/bash
set -e

echo "=== CI/CD Pipeline Started ==="
echo "Build Number: $BUILD_NUMBER"
echo "Branch: $GIT_BRANCH"
echo "Timestamp: $(date)"

# Stage 1: Code Quality Check
echo "=== Stage 1: Code Quality Check ==="
if [ -d "/workspace/src" ]; then
    echo "✓ Source directory exists"
    file_count=$(find /workspace/src -name "*.py" -o -name "*.js" | wc -l)
    echo "✓ Found $file_count source files"
else
    echo "✗ Source directory not found"
    exit 1
fi

# Stage 2: Unit Tests
echo "=== Stage 2: Unit Tests ==="
if [ -d "/workspace/tests" ]; then
    echo "✓ Tests directory exists"
    # Simulate running tests
    echo "Running unit tests..."
    sleep 1
    echo "✓ All tests passed"
else
    echo "⚠ Tests directory not found, skipping tests"
fi

# Stage 3: Build
echo "=== Stage 3: Build ==="
mkdir -p /workspace/build
echo "Building application..."
sleep 1

# Create build artifacts
echo "Application built successfully" > /workspace/build/app.txt
echo "Build completed at $(date)" > /workspace/build/build.log
echo "✓ Build completed"

# Stage 4: Package
echo "=== Stage 4: Package ==="
cd /workspace/build
tar -czf app-build-${BUILD_NUMBER}.tar.gz app.txt build.log
echo "✓ Package created: app-build-${BUILD_NUMBER}.tar.gz"

# Stage 5: Deploy (simulation)
echo "=== Stage 5: Deploy ==="
echo "Deploying to staging environment..."
sleep 1
echo "✓ Deployed successfully"

echo "=== CI/CD Pipeline Completed ==="
echo "Pipeline Duration: $((SECONDS))s"
`

		uploadTool := &tools.UploadFileTool{Manager: framework.SandboxManager}
		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id":  cicdContainer.ID,
			"file_path":   "/workspace/ci-pipeline.sh",
			"content":     ciScript,
			"permissions": "0755",
		})
		require.NoError(t, err)

		// Step 4: Create sample application code
		appCode := `#!/usr/bin/env python3
def main():
    print("Hello from CI/CD Application!")
    return 0

if __name__ == "__main__":
    exit(main())
`
		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id":  cicdContainer.ID,
			"file_path":   "/workspace/src/app.py",
			"content":     appCode,
			"permissions": "0755",
		})
		require.NoError(t, err)

		// Step 5: Create test file
		testCode := `#!/usr/bin/env python3
import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))

class TestApp(unittest.TestCase):
    def test_basic_functionality(self):
        self.assertTrue(True)
        print("Basic test passed")

if __name__ == "__main__":
    unittest.main()
`
		_, err = uploadTool.Execute(ctx, map[string]interface{}{
			"sandbox_id":  cicdContainer.ID,
			"file_path":   "/workspace/tests/test_app.py",
			"content":     testCode,
			"permissions": "0755",
		})
		require.NoError(t, err)

		// Step 6: Run CI/CD pipeline
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": cicdContainer.ID,
			"command":    "/workspace/ci-pipeline.sh",
			"timeout":    60,
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		output := result.(*tools.ExecutionResult).Stdout
		assert.Contains(t, output, "CI/CD Pipeline Started", "Pipeline should start")
		assert.Contains(t, output, "Stage 1: Code Quality Check", "Should run code quality stage")
		assert.Contains(t, output, "Stage 2: Unit Tests", "Should run test stage")
		assert.Contains(t, output, "Stage 3: Build", "Should run build stage")
		assert.Contains(t, output, "Stage 4: Package", "Should run package stage")
		assert.Contains(t, output, "Stage 5: Deploy", "Should run deploy stage")
		assert.Contains(t, output, "CI/CD Pipeline Completed", "Pipeline should complete")

		// Step 7: Verify build artifacts
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": cicdContainer.ID,
			"command":    "ls",
			"args":       []string{"-la", "/workspace/build/"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		output = result.(*tools.ExecutionResult).Stdout
		assert.Contains(t, output, "app-build-123.tar.gz", "Build package should exist")
		assert.Contains(t, output, "app.txt", "Build artifact should exist")
		assert.Contains(t, output, "build.log", "Build log should exist")

		t.Log("CI/CD pipeline simulation completed successfully")
	})
}