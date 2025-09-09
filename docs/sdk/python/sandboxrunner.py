#!/usr/bin/env python3
"""
SandboxRunner Python SDK

A comprehensive Python client library for interacting with SandboxRunner MCP Server.
Provides high-level abstractions for sandbox management, code execution, and file operations.

Usage:
    from sandboxrunner import SandboxRunner
    
    # Initialize client
    client = SandboxRunner(base_url="http://localhost:8080", api_key="your-api-key")
    
    # Create and use sandbox
    sandbox = client.create_sandbox(image="python:3.11")
    result = sandbox.run_python("print('Hello, World!')")
    print(result.stdout)
    
    # Clean up
    sandbox.terminate()

Author: SandboxRunner Team
License: MIT
Version: 5.2.0
"""

import json
import requests
import uuid
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkMode(Enum):
    """Network modes for sandbox environments"""
    NONE = "none"
    BRIDGE = "bridge"
    HOST = "host"


class SandboxStatus(Enum):
    """Sandbox status values"""
    CREATING = "creating"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class ExecutionResult:
    """Result of code execution"""
    text: str
    is_error: bool
    language: str
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool
    metadata: Dict[str, Any] = None

    @property
    def success(self) -> bool:
        """Check if execution was successful"""
        return not self.is_error and self.exit_code == 0

    def print_output(self):
        """Print formatted output"""
        if self.stdout:
            print("STDOUT:")
            print(self.stdout)
        if self.stderr:
            print("STDERR:")
            print(self.stderr)
        if self.timed_out:
            print("WARNING: Execution timed out")


@dataclass
class FileInfo:
    """Information about a file or directory"""
    name: str
    path: str
    size: int
    is_dir: bool
    mode: Optional[str] = None
    modified: Optional[str] = None


@dataclass
class SandboxInfo:
    """Information about a sandbox"""
    id: str
    container_id: str
    status: str
    working_dir: str
    created_at: str
    updated_at: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


class SandboxRunnerError(Exception):
    """Base exception for SandboxRunner errors"""
    def __init__(self, message: str, code: str = None, details: str = None):
        super().__init__(message)
        self.code = code
        self.details = details


class SandboxNotFoundError(SandboxRunnerError):
    """Raised when a sandbox is not found"""
    pass


class ExecutionError(SandboxRunnerError):
    """Raised when code execution fails"""
    pass


class APIError(SandboxRunnerError):
    """Raised when API requests fail"""
    pass


class Sandbox:
    """Represents a sandbox environment"""
    
    def __init__(self, client: 'SandboxRunner', sandbox_info: SandboxInfo):
        self.client = client
        self.info = sandbox_info
        self._id = sandbox_info.id

    @property
    def id(self) -> str:
        """Get sandbox ID"""
        return self._id

    @property
    def status(self) -> str:
        """Get current sandbox status"""
        # Refresh status
        sandboxes = self.client.list_sandboxes()
        for sb in sandboxes:
            if sb.id == self._id:
                self.info = sb
                return sb.status
        raise SandboxNotFoundError(f"Sandbox {self._id} not found")

    def run_python(self, code: str, packages: List[str] = None, 
                   files: Dict[str, str] = None, options: Dict[str, str] = None,
                   environment: Dict[str, str] = None, timeout: int = 30,
                   stdin: str = None) -> ExecutionResult:
        """Execute Python code in the sandbox"""
        return self.client.run_python(
            sandbox_id=self._id,
            code=code,
            packages=packages or [],
            files=files or {},
            options=options or {},
            environment=environment or {},
            timeout=timeout,
            stdin=stdin
        )

    def run_javascript(self, code: str, packages: List[str] = None,
                      files: Dict[str, str] = None, options: Dict[str, str] = None,
                      environment: Dict[str, str] = None, timeout: int = 30,
                      stdin: str = None) -> ExecutionResult:
        """Execute JavaScript/Node.js code in the sandbox"""
        return self.client.run_javascript(
            sandbox_id=self._id,
            code=code,
            packages=packages or [],
            files=files or {},
            options=options or {},
            environment=environment or {},
            timeout=timeout,
            stdin=stdin
        )

    def run_typescript(self, code: str, packages: List[str] = None,
                      files: Dict[str, str] = None, options: Dict[str, str] = None,
                      environment: Dict[str, str] = None, timeout: int = 30,
                      stdin: str = None) -> ExecutionResult:
        """Execute TypeScript code in the sandbox"""
        return self.client.run_typescript(
            sandbox_id=self._id,
            code=code,
            packages=packages or [],
            files=files or {},
            options=options or {},
            environment=environment or {},
            timeout=timeout,
            stdin=stdin
        )

    def run_go(self, code: str, packages: List[str] = None,
               files: Dict[str, str] = None, options: Dict[str, str] = None,
               environment: Dict[str, str] = None, timeout: int = 60,
               stdin: str = None) -> ExecutionResult:
        """Execute Go code in the sandbox"""
        return self.client.run_go(
            sandbox_id=self._id,
            code=code,
            packages=packages or [],
            files=files or {},
            options=options or {},
            environment=environment or {},
            timeout=timeout,
            stdin=stdin
        )

    def run_rust(self, code: str, packages: List[str] = None,
                 files: Dict[str, str] = None, options: Dict[str, str] = None,
                 environment: Dict[str, str] = None, timeout: int = 60,
                 stdin: str = None) -> ExecutionResult:
        """Execute Rust code in the sandbox"""
        return self.client.run_rust(
            sandbox_id=self._id,
            code=code,
            packages=packages or [],
            files=files or {},
            options=options or {},
            environment=environment or {},
            timeout=timeout,
            stdin=stdin
        )

    def run_shell(self, code: str, packages: List[str] = None,
                  files: Dict[str, str] = None, options: Dict[str, str] = None,
                  environment: Dict[str, str] = None, timeout: int = 30,
                  stdin: str = None) -> ExecutionResult:
        """Execute shell script in the sandbox"""
        return self.client.run_shell(
            sandbox_id=self._id,
            code=code,
            packages=packages or [],
            files=files or {},
            options=options or {},
            environment=environment or {},
            timeout=timeout,
            stdin=stdin
        )

    def exec_command(self, command: str, working_dir: str = None,
                     environment: Dict[str, str] = None, timeout: int = 30) -> ExecutionResult:
        """Execute shell command in the sandbox"""
        return self.client.exec_command(
            sandbox_id=self._id,
            command=command,
            working_dir=working_dir,
            environment=environment or {},
            timeout=timeout
        )

    def upload_file(self, path: str, content: str, encoding: str = "utf8"):
        """Upload file to sandbox"""
        return self.client.upload_file(
            sandbox_id=self._id,
            path=path,
            content=content,
            encoding=encoding
        )

    def download_file(self, path: str, encoding: str = "utf8") -> str:
        """Download file from sandbox"""
        return self.client.download_file(
            sandbox_id=self._id,
            path=path,
            encoding=encoding
        )

    def read_file(self, path: str, encoding: str = "utf8", max_size: int = None) -> str:
        """Read file contents from sandbox"""
        return self.client.read_file(
            sandbox_id=self._id,
            path=path,
            encoding=encoding,
            max_size=max_size
        )

    def write_file(self, path: str, content: str, encoding: str = "utf8"):
        """Write content to file in sandbox"""
        return self.client.write_file(
            sandbox_id=self._id,
            path=path,
            content=content,
            encoding=encoding
        )

    def list_files(self, path: str = "/workspace", recursive: bool = False) -> List[FileInfo]:
        """List files in sandbox directory"""
        return self.client.list_files(
            sandbox_id=self._id,
            path=path,
            recursive=recursive
        )

    def terminate(self):
        """Terminate the sandbox"""
        return self.client.terminate_sandbox(self._id)

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - automatically terminate sandbox"""
        try:
            self.terminate()
        except Exception as e:
            logger.warning(f"Failed to terminate sandbox {self._id}: {e}")


class SandboxRunner:
    """Main client class for SandboxRunner API"""
    
    def __init__(self, base_url: str = "http://localhost:8080", api_key: str = None,
                 timeout: int = 30, verify_ssl: bool = True):
        """
        Initialize SandboxRunner client
        
        Args:
            base_url: Base URL of the SandboxRunner server
            api_key: API key for authentication (if required)
            timeout: Default timeout for requests
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Setup session
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({'X-API-Key': api_key})
        self.session.headers.update({'Content-Type': 'application/json'})

    def _make_request(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make API request to SandboxRunner"""
        url = f"{self.base_url}/mcp/tools/{endpoint}"
        
        try:
            response = self.session.post(
                url,
                json=data,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise APIError(f"Request failed: {str(e)}")
        except json.JSONDecodeError:
            raise APIError("Invalid JSON response")

    def _handle_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Handle API response and check for errors"""
        if response.get('is_error', False):
            metadata = response.get('metadata', {})
            raise ExecutionError(
                response.get('text', 'Unknown error'),
                code=metadata.get('code'),
                details=metadata.get('details')
            )
        return response

    def create_sandbox(self, image: str = "ubuntu:22.04", workspace_dir: str = "/workspace",
                      environment: Dict[str, str] = None, cpu_limit: str = None,
                      memory_limit: str = None, disk_limit: str = None,
                      network_mode: NetworkMode = NetworkMode.NONE) -> Sandbox:
        """
        Create a new sandbox environment
        
        Args:
            image: Container image to use
            workspace_dir: Working directory in the container
            environment: Environment variables
            cpu_limit: CPU limit (e.g., "2.0")
            memory_limit: Memory limit (e.g., "1G")
            disk_limit: Disk limit (e.g., "10G")
            network_mode: Network configuration
            
        Returns:
            Sandbox instance
        """
        data = {
            "image": image,
            "workspace_dir": workspace_dir,
            "network_mode": network_mode.value
        }
        
        if environment:
            data["environment"] = environment
        if cpu_limit:
            data["cpu_limit"] = cpu_limit
        if memory_limit:
            data["memory_limit"] = memory_limit
        if disk_limit:
            data["disk_limit"] = disk_limit

        response = self._make_request("create_sandbox", data)
        self._handle_response(response)
        
        metadata = response.get('metadata', {})
        sandbox_info = SandboxInfo(
            id=metadata['sandbox_id'],
            container_id=metadata.get('container_id', ''),
            status=metadata.get('status', 'unknown'),
            working_dir=workspace_dir,
            created_at=metadata.get('created_at', ''),
            config=metadata.get('config', {}),
            metadata=metadata
        )
        
        logger.info(f"Created sandbox {sandbox_info.id}")
        return Sandbox(self, sandbox_info)

    def list_sandboxes(self) -> List[SandboxInfo]:
        """List all sandbox environments"""
        response = self._make_request("list_sandboxes", {})
        self._handle_response(response)
        
        # Parse sandbox list from response
        # This would need to be adapted based on actual response format
        sandboxes = []
        metadata = response.get('metadata', {})
        if 'sandboxes' in metadata:
            for sb_data in metadata['sandboxes']:
                sandbox_info = SandboxInfo(
                    id=sb_data['id'],
                    container_id=sb_data.get('container_id', ''),
                    status=sb_data.get('status', 'unknown'),
                    working_dir=sb_data.get('working_dir', '/workspace'),
                    created_at=sb_data.get('created_at', ''),
                    metadata=sb_data
                )
                sandboxes.append(sandbox_info)
        
        return sandboxes

    def terminate_sandbox(self, sandbox_id: str):
        """Terminate a sandbox environment"""
        data = {"sandbox_id": sandbox_id}
        response = self._make_request("terminate_sandbox", data)
        self._handle_response(response)
        logger.info(f"Terminated sandbox {sandbox_id}")

    def run_python(self, sandbox_id: str, code: str, packages: List[str] = None,
                   files: Dict[str, str] = None, options: Dict[str, str] = None,
                   environment: Dict[str, str] = None, working_dir: str = None,
                   timeout: int = 30, stdin: str = None) -> ExecutionResult:
        """Execute Python code in a sandbox"""
        data = {
            "sandbox_id": sandbox_id,
            "code": code,
            "packages": packages or [],
            "files": files or {},
            "options": options or {},
            "environment": environment or {},
            "timeout": timeout
        }
        
        if working_dir:
            data["working_dir"] = working_dir
        if stdin:
            data["stdin"] = stdin

        response = self._make_request("run_python", data)
        return self._parse_execution_result(response)

    def run_javascript(self, sandbox_id: str, code: str, packages: List[str] = None,
                      files: Dict[str, str] = None, options: Dict[str, str] = None,
                      environment: Dict[str, str] = None, working_dir: str = None,
                      timeout: int = 30, stdin: str = None) -> ExecutionResult:
        """Execute JavaScript/Node.js code in a sandbox"""
        data = {
            "sandbox_id": sandbox_id,
            "code": code,
            "packages": packages or [],
            "files": files or {},
            "options": options or {},
            "environment": environment or {},
            "timeout": timeout
        }
        
        if working_dir:
            data["working_dir"] = working_dir
        if stdin:
            data["stdin"] = stdin

        response = self._make_request("run_javascript", data)
        return self._parse_execution_result(response)

    def run_typescript(self, sandbox_id: str, code: str, packages: List[str] = None,
                      files: Dict[str, str] = None, options: Dict[str, str] = None,
                      environment: Dict[str, str] = None, working_dir: str = None,
                      timeout: int = 30, stdin: str = None) -> ExecutionResult:
        """Execute TypeScript code in a sandbox"""
        data = {
            "sandbox_id": sandbox_id,
            "code": code,
            "packages": packages or [],
            "files": files or {},
            "options": options or {},
            "environment": environment or {},
            "timeout": timeout
        }
        
        if working_dir:
            data["working_dir"] = working_dir
        if stdin:
            data["stdin"] = stdin

        response = self._make_request("run_typescript", data)
        return self._parse_execution_result(response)

    def run_go(self, sandbox_id: str, code: str, packages: List[str] = None,
               files: Dict[str, str] = None, options: Dict[str, str] = None,
               environment: Dict[str, str] = None, working_dir: str = None,
               timeout: int = 60, stdin: str = None) -> ExecutionResult:
        """Execute Go code in a sandbox"""
        data = {
            "sandbox_id": sandbox_id,
            "code": code,
            "packages": packages or [],
            "files": files or {},
            "options": options or {},
            "environment": environment or {},
            "timeout": timeout
        }
        
        if working_dir:
            data["working_dir"] = working_dir
        if stdin:
            data["stdin"] = stdin

        response = self._make_request("run_go", data)
        return self._parse_execution_result(response)

    def run_rust(self, sandbox_id: str, code: str, packages: List[str] = None,
                 files: Dict[str, str] = None, options: Dict[str, str] = None,
                 environment: Dict[str, str] = None, working_dir: str = None,
                 timeout: int = 60, stdin: str = None) -> ExecutionResult:
        """Execute Rust code in a sandbox"""
        data = {
            "sandbox_id": sandbox_id,
            "code": code,
            "packages": packages or [],
            "files": files or {},
            "options": options or {},
            "environment": environment or {},
            "timeout": timeout
        }
        
        if working_dir:
            data["working_dir"] = working_dir
        if stdin:
            data["stdin"] = stdin

        response = self._make_request("run_rust", data)
        return self._parse_execution_result(response)

    def run_shell(self, sandbox_id: str, code: str, packages: List[str] = None,
                  files: Dict[str, str] = None, options: Dict[str, str] = None,
                  environment: Dict[str, str] = None, working_dir: str = None,
                  timeout: int = 30, stdin: str = None) -> ExecutionResult:
        """Execute shell script in a sandbox"""
        data = {
            "sandbox_id": sandbox_id,
            "code": code,
            "packages": packages or [],
            "files": files or {},
            "options": options or {},
            "environment": environment or {},
            "timeout": timeout
        }
        
        if working_dir:
            data["working_dir"] = working_dir
        if stdin:
            data["stdin"] = stdin

        response = self._make_request("run_shell", data)
        return self._parse_execution_result(response)

    def exec_command(self, sandbox_id: str, command: str, working_dir: str = None,
                     environment: Dict[str, str] = None, timeout: int = 30) -> ExecutionResult:
        """Execute shell command in a sandbox"""
        data = {
            "sandbox_id": sandbox_id,
            "command": command,
            "timeout": timeout
        }
        
        if working_dir:
            data["working_dir"] = working_dir
        if environment:
            data["environment"] = environment

        response = self._make_request("exec_command", data)
        return self._parse_execution_result(response)

    def upload_file(self, sandbox_id: str, path: str, content: str, encoding: str = "utf8"):
        """Upload file to sandbox"""
        data = {
            "sandbox_id": sandbox_id,
            "path": path,
            "content": content,
            "encoding": encoding
        }
        
        response = self._make_request("upload_file", data)
        self._handle_response(response)

    def download_file(self, sandbox_id: str, path: str, encoding: str = "utf8") -> str:
        """Download file from sandbox"""
        data = {
            "sandbox_id": sandbox_id,
            "path": path,
            "encoding": encoding
        }
        
        response = self._make_request("download_file", data)
        self._handle_response(response)
        return response.get('metadata', {}).get('content', '')

    def read_file(self, sandbox_id: str, path: str, encoding: str = "utf8", 
                  max_size: int = None) -> str:
        """Read file contents from sandbox"""
        data = {
            "sandbox_id": sandbox_id,
            "path": path,
            "encoding": encoding
        }
        
        if max_size:
            data["max_size"] = max_size
        
        response = self._make_request("read_file", data)
        self._handle_response(response)
        return response.get('metadata', {}).get('content', '')

    def write_file(self, sandbox_id: str, path: str, content: str, encoding: str = "utf8"):
        """Write content to file in sandbox"""
        data = {
            "sandbox_id": sandbox_id,
            "path": path,
            "content": content,
            "encoding": encoding
        }
        
        response = self._make_request("write_file", data)
        self._handle_response(response)

    def list_files(self, sandbox_id: str, path: str = "/workspace", 
                   recursive: bool = False) -> List[FileInfo]:
        """List files in sandbox directory"""
        data = {
            "sandbox_id": sandbox_id,
            "path": path,
            "recursive": recursive
        }
        
        response = self._make_request("list_files", data)
        self._handle_response(response)
        
        files = []
        metadata = response.get('metadata', {})
        for file_data in metadata.get('files', []):
            file_info = FileInfo(
                name=file_data['name'],
                path=file_data['path'],
                size=file_data['size'],
                is_dir=file_data['is_dir'],
                mode=file_data.get('mode'),
                modified=file_data.get('modified')
            )
            files.append(file_info)
        
        return files

    def _parse_execution_result(self, response: Dict[str, Any]) -> ExecutionResult:
        """Parse execution result from API response"""
        metadata = response.get('metadata', {})
        
        return ExecutionResult(
            text=response.get('text', ''),
            is_error=response.get('is_error', False),
            language=metadata.get('language', ''),
            exit_code=metadata.get('exit_code', 0),
            stdout=metadata.get('stdout', ''),
            stderr=metadata.get('stderr', ''),
            duration=metadata.get('duration', 0.0),
            timed_out=metadata.get('timed_out', False),
            metadata=metadata
        )


# Convenience functions
def create_sandbox(image: str = "ubuntu:22.04", **kwargs) -> Sandbox:
    """Create a sandbox using default client"""
    client = SandboxRunner()
    return client.create_sandbox(image=image, **kwargs)


def quick_python(code: str, packages: List[str] = None, image: str = "python:3.11") -> ExecutionResult:
    """Quick Python execution with automatic cleanup"""
    client = SandboxRunner()
    with client.create_sandbox(image=image) as sandbox:
        return sandbox.run_python(code, packages=packages)


def quick_javascript(code: str, packages: List[str] = None, image: str = "node:18") -> ExecutionResult:
    """Quick JavaScript execution with automatic cleanup"""
    client = SandboxRunner()
    with client.create_sandbox(image=image) as sandbox:
        return sandbox.run_javascript(code, packages=packages)


# Example usage
if __name__ == "__main__":
    # Basic usage example
    client = SandboxRunner()
    
    # Create sandbox
    sandbox = client.create_sandbox(
        image="python:3.11",
        memory_limit="1G",
        network_mode=NetworkMode.BRIDGE
    )
    
    try:
        # Execute Python code
        result = sandbox.run_python(
            code="""
import numpy as np
print("Hello from SandboxRunner!")
print(f"NumPy version: {np.__version__}")
arr = np.array([1, 2, 3, 4, 5])
print(f"Array sum: {np.sum(arr)}")
            """,
            packages=["numpy"]
        )
        
        print("Execution successful!")
        result.print_output()
        
        # File operations
        sandbox.write_file("/workspace/test.txt", "Hello, World!")
        content = sandbox.read_file("/workspace/test.txt")
        print(f"File content: {content}")
        
        files = sandbox.list_files("/workspace")
        print("Files in workspace:")
        for file_info in files:
            print(f"  {file_info.name} ({'dir' if file_info.is_dir else 'file'})")
        
    finally:
        # Clean up
        sandbox.terminate()