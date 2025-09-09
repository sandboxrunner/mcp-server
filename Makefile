# MCP SandboxRunner Server Makefile

# Build information
VERSION ?= $(shell git describe --tags --always --dirty)
COMMIT := $(shell git rev-parse --short HEAD)
DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# Go build flags
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# Directories
BUILD_DIR := build
BIN_DIR := $(BUILD_DIR)/bin
DIST_DIR := $(BUILD_DIR)/dist

# Binary names
BINARY_NAME := mcp-sandboxd
BINARY_PATH := $(BIN_DIR)/$(BINARY_NAME)

.PHONY: all build clean test lint fmt vet deps install uninstall docker help \
	perf-bench perf-bench-quick perf-bench-container perf-bench-tools perf-bench-language perf-bench-memory perf-bench-concurrent \
	perf-load perf-load-burst perf-load-memory perf-load-recovery perf-load-longrunning \
	perf-memory perf-memory-leak perf-memory-goroutine perf-memory-concurrent perf-memory-large \
	perf-profile-cpu perf-profile-memory perf-profile-concurrency perf-profile-benchmark \
	perf-all perf-validation perf-regression perf-config perf-config-validate perf-clean

# Default target
all: clean fmt vet test build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BINARY_PATH) ./cmd/mcp-sandboxd
	@echo "Binary built: $(BINARY_PATH)"

# Build for multiple platforms
build-all: clean
	@echo "Building for multiple platforms..."
	@mkdir -p $(DIST_DIR)
	
	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/mcp-sandboxd
	
	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/mcp-sandboxd
	
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/mcp-sandboxd
	
	# macOS ARM64
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/mcp-sandboxd
	
	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/mcp-sandboxd
	
	@echo "Multi-platform builds completed in $(DIST_DIR)/"

# Run tests
test:
	@echo "Running tests..."
	go test -v -race -cover ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run integration tests
test-integration:
	@echo "Running integration tests..."
	go test -v -timeout 30m ./pkg/integration -run TestIntegration

# Run quick integration smoke test
test-integration-quick:
	@echo "Running quick integration test..."
	go test -v -timeout 5m ./pkg/integration -run TestQuickIntegration

# Run specific integration test categories
test-containers:
	@echo "Running container orchestration tests..."
	go test -v -timeout 10m ./pkg/integration -run TestMultiContainerOrchestration

test-e2e:
	@echo "Running end-to-end workflow tests..."
	go test -v -timeout 15m ./pkg/integration -run TestEndToEndUserJourneys

test-failure:
	@echo "Running failure injection and chaos tests..."
	go test -v -timeout 10m ./pkg/integration -run TestFailureInjectionAndRecovery

test-security:
	@echo "Running security boundary tests..."
	go test -v -timeout 10m ./pkg/integration -run TestSecurityBoundaries

test-chaos:
	@echo "Running chaos engineering tests..."
	go test -v -timeout 15m ./pkg/integration -run TestChaosEngineering

# Performance Testing
# =================

# Run all performance benchmarks
perf-bench:
	@echo "Running performance benchmarks..."
	go test -bench=. -benchmem -timeout 30m ./pkg/performance

# Run quick performance benchmarks
perf-bench-quick:
	@echo "Running quick performance benchmarks..."
	go test -bench=. -benchmem -short -timeout 10m ./pkg/performance

# Run specific benchmark categories
perf-bench-container:
	@echo "Running container lifecycle benchmarks..."
	go test -bench=BenchmarkContainer -benchmem -timeout 15m ./pkg/performance

perf-bench-tools:
	@echo "Running tool execution benchmarks..."
	go test -bench=BenchmarkTool -benchmem -timeout 15m ./pkg/performance

perf-bench-language:
	@echo "Running language execution benchmarks..."
	go test -bench=BenchmarkLanguage -benchmem -timeout 20m ./pkg/performance

perf-bench-memory:
	@echo "Running memory efficiency benchmarks..."
	go test -bench=BenchmarkMemory -benchmem -timeout 15m ./pkg/performance

perf-bench-concurrent:
	@echo "Running concurrent operation benchmarks..."
	go test -bench=BenchmarkConcurrent -benchmem -timeout 20m ./pkg/performance

# Load Testing
perf-load:
	@echo "Running load tests..."
	go test -v -timeout 60m ./pkg/performance -run TestSustainedHighLoad

perf-load-burst:
	@echo "Running burst traffic tests..."
	go test -v -timeout 30m ./pkg/performance -run TestBurstTrafficPatterns

perf-load-memory:
	@echo "Running memory pressure tests..."
	go test -v -timeout 45m ./pkg/performance -run TestMemoryPressure

perf-load-recovery:
	@echo "Running resource exhaustion recovery tests..."
	go test -v -timeout 60m ./pkg/performance -run TestResourceExhaustionRecovery

perf-load-longrunning:
	@echo "Running long-running operation tests..."
	go test -v -timeout 90m ./pkg/performance -run TestLongRunningOperations

# Memory Testing
perf-memory:
	@echo "Running memory usage tests..."
	go test -v -timeout 30m ./pkg/performance -run TestSandboxMemoryUsage

perf-memory-leak:
	@echo "Running memory leak detection tests..."
	go test -v -timeout 60m ./pkg/performance -run TestMemoryLeakDetection

perf-memory-goroutine:
	@echo "Running goroutine leak detection tests..."
	go test -v -timeout 30m ./pkg/performance -run TestGoroutineLeakDetection

perf-memory-concurrent:
	@echo "Running concurrent memory usage tests..."
	go test -v -timeout 45m ./pkg/performance -run TestConcurrentMemoryUsage

perf-memory-large:
	@echo "Running large data handling tests..."
	go test -v -timeout 30m ./pkg/performance -run TestLargeDataHandling

# Profiling
perf-profile-cpu:
	@echo "Running CPU profiling tests..."
	@mkdir -p $(BUILD_DIR)/profiles
	go test -v -timeout 30m ./pkg/performance -run TestCPUProfiling
	@echo "CPU profiles saved to $(BUILD_DIR)/profiles/"

perf-profile-memory:
	@echo "Running memory profiling tests..."
	@mkdir -p $(BUILD_DIR)/profiles
	go test -v -timeout 30m ./pkg/performance -run TestMemoryProfiling
	@echo "Memory profiles saved to $(BUILD_DIR)/profiles/"

perf-profile-concurrency:
	@echo "Running concurrency profiling tests..."
	@mkdir -p $(BUILD_DIR)/profiles
	go test -v -timeout 30m ./pkg/performance -run TestConcurrencyProfiling
	@echo "Concurrency profiles saved to $(BUILD_DIR)/profiles/"

perf-profile-benchmark:
	@echo "Running benchmark profiling tests..."
	@mkdir -p $(BUILD_DIR)/profiles
	go test -v -timeout 60m ./pkg/performance -run TestBenchmarkWithProfiling
	@echo "Benchmark profiles saved to $(BUILD_DIR)/profiles/"

# Generate performance configuration
perf-config:
	@echo "Generating performance test configuration..."
	@mkdir -p config
	go run -ldflags "$(LDFLAGS)" ./cmd/perf-config-gen -o config/performance.yaml

# Validate performance configuration
perf-config-validate:
	@echo "Validating performance configuration..."
	go run -ldflags "$(LDFLAGS)" ./cmd/perf-config-gen -validate config/performance.yaml

# Comprehensive performance test suite
perf-all:
	@echo "Running comprehensive performance test suite..."
	@echo "This will take 2-3 hours to complete..."
	@mkdir -p $(BUILD_DIR)/perf-reports
	$(MAKE) perf-bench
	$(MAKE) perf-load
	$(MAKE) perf-memory
	@echo ""
	@echo "Performance test suite completed!"
	@echo "Check $(BUILD_DIR)/perf-reports/ for detailed results"

# Quick performance validation (CI-friendly)
perf-validation:
	@echo "Running quick performance validation..."
	go test -v -short -timeout 10m ./pkg/performance -run "TestSandboxMemoryUsage|TestGoroutineLeakDetection"
	$(MAKE) perf-bench-quick

# Performance regression tests
perf-regression:
	@echo "Running performance regression tests..."
	@echo "Comparing against baseline metrics..."
	go test -v -timeout 45m ./pkg/performance -run "TestContainerStartup|TestAPIResponseTime|TestMemoryEfficiency"

# Clean performance test artifacts
perf-clean:
	@echo "Cleaning performance test artifacts..."
	@rm -rf $(BUILD_DIR)/profiles
	@rm -rf $(BUILD_DIR)/perf-reports
	@rm -f *.prof *.out

# Run performance benchmarks
bench-integration:
	@echo "Running integration benchmarks..."
	go test -bench=. -benchmem ./pkg/integration -timeout 10m

# Run all tests including integration
test-all: test test-integration
	@echo "All tests completed successfully!"

# Lint code
lint:
	@echo "Running golangci-lint..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	golangci-lint run

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Vet code
vet:
	@echo "Running go vet..."
	go vet ./...

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Install binary to GOPATH/bin
install: build
	@echo "Installing $(BINARY_NAME)..."
	go install $(LDFLAGS) ./cmd/mcp-sandboxd

# Uninstall binary from GOPATH/bin
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@rm -f $(shell go env GOPATH)/bin/$(BINARY_NAME)

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html

# Run the server
run: build
	@echo "Running $(BINARY_NAME)..."
	$(BINARY_PATH)

# Run with config file
run-config: build
	@echo "Running $(BINARY_NAME) with config..."
	$(BINARY_PATH) --config config/mcp-sandboxd.yaml

# Generate default config
config:
	@echo "Generating default configuration..."
	@mkdir -p config
	$(BINARY_PATH) config generate -o config/mcp-sandboxd.yaml

# Validate config
validate-config:
	@echo "Validating configuration..."
	$(BINARY_PATH) config validate --config config/mcp-sandboxd.yaml

# Docker build
docker:
	@echo "Building Docker image..."
	docker build -t sandboxrunner/mcp-server:$(VERSION) .
	docker tag sandboxrunner/mcp-server:$(VERSION) sandboxrunner/mcp-server:latest

# Docker run
docker-run:
	@echo "Running Docker container..."
	docker run --rm -it \
		-v $(PWD)/config:/app/config \
		-v /tmp/sandboxrunner:/tmp/sandboxrunner \
		sandboxrunner/mcp-server:latest

# Development server with live reload
dev:
	@echo "Starting development server..."
	@which air > /dev/null || (echo "air not found. Install with: go install github.com/cosmtrek/air@latest" && exit 1)
	air

# Initialize project (download deps, generate config, etc.)
init: deps config
	@echo "Project initialized successfully!"
	@echo ""
	@echo "To run the server:"
	@echo "  make run"
	@echo ""
	@echo "To run with config:"
	@echo "  make run-config"
	@echo ""
	@echo "Configuration file: config/mcp-sandboxd.yaml"

# Show help
help:
	@echo "MCP SandboxRunner Server Build Commands"
	@echo ""
	@echo "Building:"
	@echo "  build      - Build the binary"
	@echo "  build-all  - Build for multiple platforms"
	@echo "  install    - Install binary to GOPATH/bin"
	@echo "  uninstall  - Remove binary from GOPATH/bin"
	@echo ""
	@echo "Testing:"
	@echo "  test                    - Run unit tests"
	@echo "  test-coverage          - Run tests with coverage report"
	@echo "  test-integration       - Run full integration test suite"
	@echo "  test-integration-quick - Run quick integration smoke test"
	@echo "  test-containers        - Run container orchestration tests"
	@echo "  test-e2e               - Run end-to-end workflow tests"
	@echo "  test-failure           - Run failure injection tests"
	@echo "  test-security          - Run security boundary tests"
	@echo "  test-chaos             - Run chaos engineering tests"
	@echo "  test-all               - Run all tests (unit + integration)"
	@echo "  bench-integration      - Run integration benchmarks"
	@echo "  lint                   - Run golangci-lint"
	@echo "  fmt                    - Format code"
	@echo "  vet                    - Run go vet"
	@echo ""
	@echo "Performance Testing:"
	@echo "  perf-bench             - Run all performance benchmarks"
	@echo "  perf-bench-quick       - Run quick performance benchmarks"
	@echo "  perf-bench-container   - Run container lifecycle benchmarks"
	@echo "  perf-bench-tools       - Run tool execution benchmarks"
	@echo "  perf-bench-language    - Run language execution benchmarks"
	@echo "  perf-bench-memory      - Run memory efficiency benchmarks"
	@echo "  perf-bench-concurrent  - Run concurrent operation benchmarks"
	@echo "  perf-load              - Run sustained load tests"
	@echo "  perf-load-burst        - Run burst traffic tests"
	@echo "  perf-load-memory       - Run memory pressure tests"
	@echo "  perf-load-recovery     - Run resource exhaustion tests"
	@echo "  perf-load-longrunning  - Run long-running operation tests"
	@echo "  perf-memory            - Run memory usage tests"
	@echo "  perf-memory-leak       - Run memory leak detection tests"
	@echo "  perf-memory-goroutine  - Run goroutine leak detection tests"
	@echo "  perf-memory-concurrent - Run concurrent memory tests"
	@echo "  perf-memory-large      - Run large data handling tests"
	@echo "  perf-profile-cpu       - Run CPU profiling tests"
	@echo "  perf-profile-memory    - Run memory profiling tests"
	@echo "  perf-profile-concurrency - Run concurrency profiling tests"
	@echo "  perf-profile-benchmark - Run benchmark profiling tests"
	@echo "  perf-all               - Run comprehensive performance suite"
	@echo "  perf-validation        - Run quick performance validation"
	@echo "  perf-regression        - Run performance regression tests"
	@echo "  perf-config            - Generate performance test config"
	@echo "  perf-config-validate   - Validate performance config"
	@echo "  perf-clean             - Clean performance artifacts"
	@echo ""
	@echo "Running:"
	@echo "  run        - Build and run the server"
	@echo "  run-config - Run with config file"
	@echo "  dev        - Development server with live reload"
	@echo ""
	@echo "Configuration:"
	@echo "  config          - Generate default config"
	@echo "  validate-config - Validate config file"
	@echo ""
	@echo "Docker:"
	@echo "  docker     - Build Docker image"
	@echo "  docker-run - Run Docker container"
	@echo ""
	@echo "Utilities:"
	@echo "  deps  - Download dependencies"
	@echo "  clean - Clean build artifacts"
	@echo "  init  - Initialize project"
	@echo "  help  - Show this help"