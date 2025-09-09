# run_python

Executes Python code with support for pip package installation and virtual environments.

## Description

The `run_python` tool provides comprehensive Python code execution capabilities within sandbox environments. It supports automatic package installation via pip, virtual environment creation, and execution of Python scripts with full standard library access.

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `sandbox_id` | string | Yes | - | Unique identifier of the target sandbox |
| `code` | string | Yes | - | Python code to execute |
| `packages` | array[string] | No | `[]` | Python packages to install via pip |
| `files` | object | No | `{}` | Additional files to create in workspace |
| `options` | object | No | `{}` | Python-specific execution options |
| `environment` | object | No | `{}` | Environment variables for execution |
| `working_dir` | string | No | `/workspace` | Working directory for execution |
| `timeout` | integer | No | `30` | Execution timeout in seconds (1-300) |
| `stdin` | string | No | - | Standard input to provide to the program |

### Parameter Details

#### `sandbox_id`
UUID of the sandbox environment where code will be executed:
- Format: `^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`
- Example: `"12345678-1234-1234-1234-123456789abc"`

#### `code`
Python code to execute. Can be a single expression, multiple statements, or complete scripts:
```python
# Simple expression
"print('Hello, World!')"

# Multiple statements
"""
import math
radius = 5
area = math.pi * radius ** 2
print(f'Circle area: {area:.2f}')
"""

# Script with functions
"""
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

for i in range(10):
    print(f'fib({i}) = {fibonacci(i)}')
"""
```

#### `packages`
Python packages to install automatically before code execution:
```json
[
  "numpy",                    // Latest version
  "pandas>=1.3.0",           // Version constraint
  "matplotlib==3.5.2",       // Exact version
  "scikit-learn>=1.0,<2.0",  // Range constraint
  "requests[security]",       // With extras
  "git+https://github.com/user/repo.git"  // From Git
]
```

#### `files`
Additional files to create in the workspace before execution:
```json
{
  "data.csv": "name,age,city\nAlice,30,NYC\nBob,25,LA",
  "config.json": "{\"debug\": true, \"port\": 8000}",
  "utils.py": "def helper_function():\n    return 'Hello from utils'"
}
```

#### `options`
Python-specific execution options:
```json
{
  "use_venv": "true",           // Use virtual environment
  "python_cmd": "python3.11",  // Specific Python command
  "pip_args": "--no-deps",     // Additional pip arguments
  "install_jupyter": "true"    // Install Jupyter for notebook support
}
```

#### `environment`
Environment variables for Python execution:
```json
{
  "PYTHONPATH": "/workspace:/workspace/lib",
  "PYTHONUNBUFFERED": "1",
  "PYTHONDONTWRITEBYTECODE": "1",
  "MPLBACKEND": "Agg"
}
```

#### `stdin`
Input to provide to interactive Python programs:
```json
{
  "stdin": "Alice\n25\nNew York\n"
}
```

## Response

### Success Response
```json
{
  "text": "Hello, World!\nPython version: 3.11.0\nNumPy version: 1.21.0\nArray: [1 2 3 4 5]\nSum: 15",
  "is_error": false,
  "metadata": {
    "language": "python",
    "exit_code": 0,
    "stdout": "Hello, World!\nPython version: 3.11.0\nNumPy version: 1.21.0\nArray: [1 2 3 4 5]\nSum: 15\n",
    "stderr": "",
    "duration": 2.543,
    "timed_out": false,
    "packages_installed": ["numpy==1.21.0"],
    "python_version": "3.11.0",
    "virtual_env": "/workspace/.venv",
    "files_created": ["main.py"]
  }
}
```

### Error Response
```json
{
  "text": "Python execution failed: ModuleNotFoundError: No module named 'nonexistent'",
  "is_error": true,
  "metadata": {
    "language": "python",
    "exit_code": 1,
    "stdout": "",
    "stderr": "Traceback (most recent call last):\n  File \"main.py\", line 1, in <module>\n    import nonexistent\nModuleNotFoundError: No module named 'nonexistent'",
    "duration": 0.123,
    "timed_out": false,
    "error_type": "ModuleNotFoundError",
    "error_line": 1
  }
}
```

## Examples

### Simple Python Script
```json
{
  "tool": "run_python",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "print('Hello, World!')\nprint(f'2 + 2 = {2 + 2}')"
  }
}
```

### Data Science with NumPy and Pandas
```json
{
  "tool": "run_python",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "import numpy as np\nimport pandas as pd\n\n# Create sample data\ndata = np.random.randn(100, 4)\ndf = pd.DataFrame(data, columns=['A', 'B', 'C', 'D'])\n\nprint('Dataset shape:', df.shape)\nprint('\\nFirst 5 rows:')\nprint(df.head())\nprint('\\nStatistics:')\nprint(df.describe())",
    "packages": ["numpy>=1.21.0", "pandas>=1.3.0"]
  }
}
```

### Web Scraping with Requests and BeautifulSoup
```json
{
  "tool": "run_python",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "import requests\nfrom bs4 import BeautifulSoup\n\n# Fetch webpage\nresponse = requests.get('https://httpbin.org/html')\nprint(f'Status: {response.status_code}')\n\n# Parse HTML\nsoup = BeautifulSoup(response.text, 'html.parser')\ntitle = soup.find('title').text\nprint(f'Page title: {title}')",
    "packages": ["requests", "beautifulsoup4"],
    "options": {
      "use_venv": "true"
    }
  }
}
```

### Multi-file Python Project
```json
{
  "tool": "run_python",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "from calculator import Calculator\nfrom data_processor import process_data\n\ncalc = Calculator()\nresult = calc.add(10, 5)\nprint(f'10 + 5 = {result}')\n\ndata = [1, 2, 3, 4, 5]\nprocessed = process_data(data)\nprint(f'Processed data: {processed}')",
    "files": {
      "calculator.py": "class Calculator:\n    def add(self, a, b):\n        return a + b\n    \n    def multiply(self, a, b):\n        return a * b",
      "data_processor.py": "def process_data(data):\n    return [x * 2 for x in data]"
    }
  }
}
```

### Flask Web Application
```json
{
  "tool": "run_python",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "from flask import Flask, jsonify\nfrom datetime import datetime\n\napp = Flask(__name__)\n\n@app.route('/')\ndef hello():\n    return jsonify({\n        'message': 'Hello from Flask!',\n        'timestamp': datetime.now().isoformat()\n    })\n\n@app.route('/health')\ndef health():\n    return jsonify({'status': 'OK'})\n\nif __name__ == '__main__':\n    print('Flask app created successfully')\n    print('Routes:')\n    for rule in app.url_map.iter_rules():\n        print(f'  {rule.endpoint}: {rule.rule}')",
    "packages": ["flask>=2.0.0"],
    "options": {
      "use_venv": "true"
    }
  }
}
```

### Interactive Input Handling
```json
{
  "tool": "run_python",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "name = input('Enter your name: ')\nage = int(input('Enter your age: '))\ncity = input('Enter your city: ')\n\nprint(f'Hello {name}!')\nprint(f'You are {age} years old and live in {city}.')\n\nif age >= 18:\n    print('You are an adult.')\nelse:\n    print(f'You will be an adult in {18 - age} years.')",
    "stdin": "Alice\n25\nNew York\n"
  }
}
```

### Machine Learning with Scikit-learn
```json
{
  "tool": "run_python",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "from sklearn.datasets import make_classification\nfrom sklearn.model_selection import train_test_split\nfrom sklearn.ensemble import RandomForestClassifier\nfrom sklearn.metrics import accuracy_score, classification_report\n\n# Generate sample data\nX, y = make_classification(n_samples=1000, n_features=20, n_classes=2, random_state=42)\nX_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)\n\n# Train model\nmodel = RandomForestClassifier(n_estimators=100, random_state=42)\nmodel.fit(X_train, y_train)\n\n# Make predictions\ny_pred = model.predict(X_test)\naccuracy = accuracy_score(y_test, y_pred)\n\nprint(f'Model accuracy: {accuracy:.3f}')\nprint('\\nClassification Report:')\nprint(classification_report(y_test, y_pred))",
    "packages": ["scikit-learn>=1.0.0", "numpy", "scipy"],
    "timeout": 60
  }
}
```

## Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| `PYTHON_SYNTAX_ERROR` | Code has syntax errors | Fix Python syntax |
| `MODULE_NOT_FOUND` | Required module not found | Add package to `packages` list |
| `PACKAGE_INSTALL_FAILED` | pip install failed | Check package name and version |
| `EXECUTION_TIMEOUT` | Code execution timed out | Increase `timeout` or optimize code |
| `IMPORT_ERROR` | Module import failed | Verify package dependencies |
| `RUNTIME_ERROR` | Runtime exception occurred | Debug code logic |
| `MEMORY_ERROR` | Out of memory | Reduce data size or increase sandbox memory |

## Best Practices

### Package Management
```json
{
  "packages": [
    "numpy==1.21.5",        // Pin versions for reproducibility
    "pandas>=1.3.0,<2.0",   // Use version ranges for compatibility
    "requests[security]",   // Include extras when needed
    "setuptools>=45"        // Include build dependencies
  ]
}
```

### Performance Optimization
- Use virtual environments for isolation: `"use_venv": "true"`
- Set appropriate timeout values for long-running operations
- Consider memory usage for large datasets
- Use compiled packages (NumPy, Pandas) for performance

### Error Handling
```python
import sys
import traceback

try:
    # Your code here
    result = risky_operation()
    print(f"Success: {result}")
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)
```

### Environment Configuration
```json
{
  "environment": {
    "PYTHONPATH": "/workspace:/workspace/lib",
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "MPLBACKEND": "Agg",
    "NUMBA_DISABLE_JIT": "1"
  }
}
```

### Security Considerations
- Use virtual environments to isolate dependencies
- Avoid installing packages with known vulnerabilities
- Validate user input in interactive scripts
- Use appropriate timeout values

## Related Tools

- [`run_code`](./run_code.md) - Generic code execution with auto-detection
- [`run_jupyter`](./run_jupyter.md) - Jupyter notebook execution
- [`create_sandbox`](./create_sandbox.md) - Create Python-optimized sandboxes
- [`upload_file`](./upload_file.md) - Upload Python modules and data files

## Advanced Usage

### Custom Python Environment
```json
{
  "options": {
    "python_cmd": "python3.11",
    "use_venv": "true",
    "pip_args": "--no-cache-dir --no-deps",
    "requirements_file": "requirements.txt"
  },
  "files": {
    "requirements.txt": "numpy==1.21.5\npandas==1.3.5\nmatplotlib==3.5.2"
  }
}
```

### Jupyter Notebook Support
```json
{
  "options": {
    "install_jupyter": "true",
    "notebook_format": "true"
  },
  "code": "# This will be executed as a Jupyter notebook\nimport matplotlib.pyplot as plt\nimport numpy as np\n\nx = np.linspace(0, 10, 100)\ny = np.sin(x)\n\nplt.plot(x, y)\nplt.title('Sine Wave')\nplt.savefig('/workspace/plot.png')\nprint('Plot saved to plot.png')"
}
```

## Troubleshooting

### Common Issues

1. **Package Installation Failures**
   ```python
   # Check pip version and upgrade
   import subprocess
   subprocess.run([sys.executable, '-m', 'pip', '--version'])
   ```

2. **Import Errors**
   ```python
   import sys
   print("Python path:")
   for path in sys.path:
       print(f"  {path}")
   ```

3. **Memory Issues**
   ```python
   import psutil
   memory = psutil.virtual_memory()
   print(f"Available memory: {memory.available / 1024**3:.2f} GB")
   ```

4. **Virtual Environment Issues**
   ```bash
   # Check virtual environment
   which python
   pip list
   ```