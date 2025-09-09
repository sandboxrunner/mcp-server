# run_javascript

Executes JavaScript/Node.js code with support for npm package installation and modern JavaScript features.

## Description

The `run_javascript` tool provides comprehensive JavaScript and Node.js code execution capabilities within sandbox environments. It supports automatic npm package installation, modern JavaScript syntax (ES2020+), async/await patterns, and popular Node.js frameworks.

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `sandbox_id` | string | Yes | - | Unique identifier of the target sandbox |
| `code` | string | Yes | - | JavaScript/Node.js code to execute |
| `packages` | array[string] | No | `[]` | NPM packages to install automatically |
| `files` | object | No | `{}` | Additional files to create in workspace |
| `options` | object | No | `{}` | JavaScript-specific execution options |
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
JavaScript/Node.js code to execute. Supports modern syntax and patterns:
```javascript
// Modern JavaScript with async/await
const fetchData = async () => {
  const response = await fetch('https://api.example.com/data');
  return await response.json();
};

// ES6+ features
const numbers = [1, 2, 3, 4, 5];
const doubled = numbers.map(n => n * 2);
const sum = numbers.reduce((a, b) => a + b, 0);

console.log('Doubled:', doubled);
console.log('Sum:', sum);
```

#### `packages`
NPM packages to install automatically before code execution:
```json
[
  "lodash",                    // Latest version
  "express@^4.18.0",          // Version range
  "axios@1.5.0",              // Exact version
  "moment@>=2.29.0",          // Minimum version
  "@types/node",              // TypeScript definitions
  "react@latest",             // Explicit latest
  "@babel/core@beta"          // Pre-release versions
]
```

#### `files`
Additional files to create in the workspace before execution:
```json
{
  "package.json": "{\"name\": \"app\", \"main\": \"index.js\", \"dependencies\": {}}",
  "config.json": "{\"port\": 3000, \"debug\": true}",
  "utils.js": "module.exports = { helper: () => 'Hello from utils' };",
  "data.txt": "Sample data file content"
}
```

#### `options`
JavaScript-specific execution options:
```json
{
  "node_version": "18",        // Node.js version to use
  "npm_registry": "https://registry.npmjs.org/",
  "npm_cache": "/tmp/.npm",    // NPM cache directory
  "enable_es_modules": "true", // Enable ES module support
  "max_old_space_size": "1024" // V8 heap size in MB
}
```

#### `environment`
Environment variables for JavaScript execution:
```json
{
  "NODE_ENV": "development",
  "NPM_CONFIG_CACHE": "/tmp/.npm",
  "NODE_OPTIONS": "--max-old-space-size=1024",
  "DEBUG": "*",
  "PORT": "3000"
}
```

#### `stdin`
Input to provide to interactive JavaScript programs:
```json
{
  "stdin": "Alice\n25\nDeveloper\n"
}
```

## Response

### Success Response
```json
{
  "text": "Hello, World!\nNode.js version: v18.17.0\nArray: [ 1, 2, 3, 4, 5 ]\nSum: 15",
  "is_error": false,
  "metadata": {
    "language": "javascript",
    "exit_code": 0,
    "stdout": "Hello, World!\nNode.js version: v18.17.0\nArray: [ 1, 2, 3, 4, 5 ]\nSum: 15\n",
    "stderr": "",
    "duration": 1.234,
    "timed_out": false,
    "packages_installed": ["lodash@4.17.21"],
    "node_version": "v18.17.0",
    "npm_version": "9.6.7",
    "files_created": ["index.js", "package.json"]
  }
}
```

### Error Response
```json
{
  "text": "JavaScript execution failed: ReferenceError: unknownVariable is not defined",
  "is_error": true,
  "metadata": {
    "language": "javascript",
    "exit_code": 1,
    "stdout": "",
    "stderr": "ReferenceError: unknownVariable is not defined\n    at Object.<anonymous> (/workspace/index.js:1:1)\n    at Module._compile (node:internal/modules/cjs/loader:1126:14)",
    "duration": 0.089,
    "timed_out": false,
    "error_type": "ReferenceError",
    "error_line": 1
  }
}
```

## Examples

### Simple JavaScript Script
```json
{
  "tool": "run_javascript",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "console.log('Hello, World!');\nconsole.log('Node.js version:', process.version);\nconst arr = [1, 2, 3, 4, 5];\nconsole.log('Array:', arr);\nconsole.log('Sum:', arr.reduce((a, b) => a + b, 0));"
  }
}
```

### Express.js Web Server
```json
{
  "tool": "run_javascript",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "const express = require('express');\nconst app = express();\nconst port = 3000;\n\napp.use(express.json());\n\napp.get('/', (req, res) => {\n  res.json({\n    message: 'Hello World!',\n    timestamp: new Date().toISOString(),\n    nodeVersion: process.version\n  });\n});\n\napp.get('/health', (req, res) => {\n  res.json({\n    status: 'OK',\n    uptime: process.uptime(),\n    memory: process.memoryUsage()\n  });\n});\n\napp.post('/echo', (req, res) => {\n  res.json({ received: req.body });\n});\n\nconsole.log('Express app configured successfully');\nconsole.log('Available routes:');\napp._router.stack.forEach((middleware, i) => {\n  if (middleware.route) {\n    console.log(`${Object.keys(middleware.route.methods)[0].toUpperCase()} ${middleware.route.path}`);\n  }\n});\n\n// For demo - in production you'd call app.listen(port)\nconsole.log(`Server would listen on port ${port}`);\n",
    "packages": ["express"]
  }
}
```

### Async/Await with HTTP Requests
```json
{
  "tool": "run_javascript",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "const axios = require('axios');\n\nasync function fetchData() {\n  try {\n    console.log('Fetching data from API...');\n    \n    const response = await axios.get('https://jsonplaceholder.typicode.com/posts/1');\n    console.log('Response status:', response.status);\n    console.log('Post data:', JSON.stringify(response.data, null, 2));\n    \n    // Multiple async operations\n    const [users, posts] = await Promise.all([\n      axios.get('https://jsonplaceholder.typicode.com/users/1'),\n      axios.get('https://jsonplaceholder.typicode.com/posts?userId=1')\n    ]);\n    \n    console.log('\\nUser:', users.data.name);\n    console.log('Total posts by user:', posts.data.length);\n    \n    return {\n      user: users.data,\n      postCount: posts.data.length\n    };\n  } catch (error) {\n    console.error('Error fetching data:', error.message);\n    throw error;\n  }\n}\n\n// Execute async function\nfetchData()\n  .then(result => {\n    console.log('\\nOperation completed successfully!');\n    console.log('Result:', result);\n  })\n  .catch(error => {\n    console.error('Operation failed:', error.message);\n    process.exit(1);\n  });",
    "packages": ["axios"]
  }
}
```

### Data Processing with Lodash
```json
{
  "tool": "run_javascript",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "const _ = require('lodash');\n\n// Sample data\nconst employees = [\n  { name: 'Alice', department: 'Engineering', salary: 95000, years: 3 },\n  { name: 'Bob', department: 'Marketing', salary: 65000, years: 2 },\n  { name: 'Charlie', department: 'Engineering', salary: 110000, years: 5 },\n  { name: 'Diana', department: 'Sales', salary: 70000, years: 1 },\n  { name: 'Eve', department: 'Engineering', salary: 85000, years: 2 }\n];\n\nconsole.log('Employee Data Analysis');\nconsole.log('====================');\n\n// Group by department\nconst byDepartment = _.groupBy(employees, 'department');\nconsole.log('\\nEmployees by Department:');\n_.forEach(byDepartment, (emps, dept) => {\n  console.log(`${dept}: ${emps.length} employees`);\n});\n\n// Calculate average salary by department\nconsole.log('\\nAverage Salary by Department:');\n_.forEach(byDepartment, (emps, dept) => {\n  const avgSalary = _.meanBy(emps, 'salary');\n  console.log(`${dept}: $${avgSalary.toLocaleString()}`);\n});\n\n// Find top earners\nconst topEarners = _.orderBy(employees, 'salary', 'desc').slice(0, 3);\nconsole.log('\\nTop 3 Earners:');\ntopEarners.forEach((emp, i) => {\n  console.log(`${i + 1}. ${emp.name} - $${emp.salary.toLocaleString()}`);\n});\n\n// Statistical analysis\nconst salaries = _.map(employees, 'salary');\nconsole.log('\\nSalary Statistics:');\nconsole.log(`Average: $${_.mean(salaries).toLocaleString()}`);\nconsole.log(`Median: $${_.sortBy(salaries)[Math.floor(salaries.length / 2)].toLocaleString()}`);\nconsole.log(`Min: $${_.min(salaries).toLocaleString()}`);\nconsole.log(`Max: $${_.max(salaries).toLocaleString()}`);\n\n// Experience analysis\nconst experienceGroups = _.groupBy(employees, emp => {\n  if (emp.years <= 1) return 'Entry Level';\n  if (emp.years <= 3) return 'Mid Level';\n  return 'Senior Level';\n});\n\nconsole.log('\\nExperience Level Distribution:');\n_.forEach(experienceGroups, (emps, level) => {\n  console.log(`${level}: ${emps.length} employees`);\n});",
    "packages": ["lodash"]
  }
}
```

### File System Operations
```json
{
  "tool": "run_javascript",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "const fs = require('fs').promises;\nconst path = require('path');\n\nasync function fileOperations() {\n  console.log('File System Operations Demo');\n  console.log('============================');\n  \n  // Create directory structure\n  await fs.mkdir('/workspace/data', { recursive: true });\n  await fs.mkdir('/workspace/output', { recursive: true });\n  \n  // Write sample data\n  const sampleData = {\n    users: [\n      { id: 1, name: 'Alice', email: 'alice@example.com' },\n      { id: 2, name: 'Bob', email: 'bob@example.com' }\n    ],\n    timestamp: new Date().toISOString()\n  };\n  \n  await fs.writeFile(\n    '/workspace/data/users.json',\n    JSON.stringify(sampleData, null, 2)\n  );\n  \n  console.log('Created users.json');\n  \n  // Read and process data\n  const userData = JSON.parse(\n    await fs.readFile('/workspace/data/users.json', 'utf8')\n  );\n  \n  console.log('Read user data:');\n  userData.users.forEach(user => {\n    console.log(`  - ${user.name} (${user.email})`);\n  });\n  \n  // Generate report\n  const report = `User Report\n============\nGenerated: ${new Date().toLocaleString()}\nTotal Users: ${userData.users.length}\n\nUsers:\n${userData.users.map(u => `- ${u.name} (${u.email})`).join('\\n')}\n`;\n  \n  await fs.writeFile('/workspace/output/report.txt', report);\n  console.log('\\nGenerated report.txt');\n  \n  // List all created files\n  const dataFiles = await fs.readdir('/workspace/data');\n  const outputFiles = await fs.readdir('/workspace/output');\n  \n  console.log('\\nCreated files:');\n  console.log('Data files:', dataFiles);\n  console.log('Output files:', outputFiles);\n  \n  // File stats\n  for (const file of [...dataFiles, ...outputFiles]) {\n    const filePath = dataFiles.includes(file) \n      ? `/workspace/data/${file}` \n      : `/workspace/output/${file}`;\n    \n    const stats = await fs.stat(filePath);\n    console.log(`${file}: ${stats.size} bytes, modified ${stats.mtime.toLocaleString()}`);\n  }\n}\n\nfileOperations().catch(console.error);"
  }
}
```

### Interactive Input Handling
```json
{
  "tool": "run_javascript",
  "parameters": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "code": "const readline = require('readline');\n\nconst rl = readline.createInterface({\n  input: process.stdin,\n  output: process.stdout\n});\n\nfunction askQuestion(question) {\n  return new Promise((resolve) => {\n    rl.question(question, (answer) => {\n      resolve(answer.trim());\n    });\n  });\n}\n\nasync function interactiveDemo() {\n  console.log('Welcome to the Interactive Demo!');\n  console.log('================================');\n  \n  try {\n    const name = await askQuestion('What is your name? ');\n    const age = await askQuestion('What is your age? ');\n    const hobby = await askQuestion('What is your favorite hobby? ');\n    \n    console.log('\\nThank you for the information!');\n    console.log(`Name: ${name}`);\n    console.log(`Age: ${age}`);\n    console.log(`Favorite hobby: ${hobby}`);\n    \n    const currentYear = new Date().getFullYear();\n    const birthYear = currentYear - parseInt(age);\n    \n    console.log(`\\nBased on your age, you were born around ${birthYear}.`);\n    \n    if (parseInt(age) >= 18) {\n      console.log('You are an adult!');\n    } else {\n      const yearsToAdult = 18 - parseInt(age);\n      console.log(`You will be an adult in ${yearsToAdult} years.`);\n    }\n    \n  } catch (error) {\n    console.error('Error:', error.message);\n  } finally {\n    rl.close();\n  }\n}\n\ninteractiveDemo();",
    "stdin": "Alice\\n25\\nProgramming\\n"
  }
}
```

## Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| `JAVASCRIPT_SYNTAX_ERROR` | Code has syntax errors | Fix JavaScript syntax |
| `MODULE_NOT_FOUND` | Required module not found | Add package to `packages` list |
| `NPM_INSTALL_FAILED` | npm install failed | Check package name and version |
| `EXECUTION_TIMEOUT` | Code execution timed out | Increase `timeout` or optimize code |
| `REFERENCE_ERROR` | Variable or function not defined | Check variable declarations |
| `TYPE_ERROR` | Type-related runtime error | Verify data types and operations |
| `PROMISE_REJECTION` | Unhandled promise rejection | Add proper error handling |
| `MEMORY_ERROR` | Out of memory | Increase heap size or optimize code |

## Best Practices

### Package Management
```json
{
  "packages": [
    "express@^4.18.0",     // Use semver ranges for flexibility
    "lodash@4.17.21",      // Pin versions for reproducibility
    "@types/node@^18.0.0", // Include TypeScript definitions
    "axios@latest"         // Use latest for development
  ]
}
```

### Error Handling
```javascript
// Proper async error handling
async function robustFunction() {
  try {
    const result = await riskyOperation();
    return result;
  } catch (error) {
    console.error('Operation failed:', error.message);
    // Log additional context
    console.error('Stack trace:', error.stack);
    throw error; // Re-throw if needed
  }
}

// Promise error handling
Promise.resolve()
  .then(() => riskyOperation())
  .catch(error => {
    console.error('Promise rejected:', error);
  });

// Unhandled rejection handling
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});
```

### Performance Optimization
```json
{
  "environment": {
    "NODE_OPTIONS": "--max-old-space-size=2048", // Increase heap size
    "UV_THREADPOOL_SIZE": "4"                    // Adjust thread pool
  },
  "options": {
    "enable_es_modules": "true",  // Use ES modules for better performance
    "npm_cache": "/tmp/.npm"      // Cache packages
  }
}
```

### Security Considerations
```javascript
// Input validation
function validateInput(input) {
  if (typeof input !== 'string' || input.length > 1000) {
    throw new Error('Invalid input');
  }
  return input.trim();
}

// Environment variable validation
const port = parseInt(process.env.PORT) || 3000;
if (port < 1 || port > 65535) {
  throw new Error('Invalid port number');
}
```

## Related Tools

- [`run_code`](./run_code.md) - Generic code execution with auto-detection
- [`run_typescript`](./run_typescript.md) - TypeScript compilation and execution
- [`create_sandbox`](./create_sandbox.md) - Create Node.js-optimized sandboxes
- [`upload_file`](./upload_file.md) - Upload JavaScript modules and configuration files

## Advanced Usage

### Custom Node.js Environment
```json
{
  "options": {
    "node_version": "18",
    "npm_registry": "https://registry.npmjs.org/",
    "enable_es_modules": "true"
  },
  "environment": {
    "NODE_ENV": "development",
    "NODE_OPTIONS": "--experimental-modules --max-old-space-size=2048"
  },
  "files": {
    "package.json": "{\"type\": \"module\", \"engines\": {\"node\": \">=18.0.0\"}}"
  }
}
```

### Microservice Template
```json
{
  "code": "import express from 'express';\nimport cors from 'cors';\nimport helmet from 'helmet';\nimport rateLimit from 'express-rate-limit';\n\nconst app = express();\nconst port = process.env.PORT || 3000;\n\n// Security middleware\napp.use(helmet());\napp.use(cors());\n\n// Rate limiting\nconst limiter = rateLimit({\n  windowMs: 15 * 60 * 1000, // 15 minutes\n  max: 100 // limit each IP to 100 requests per windowMs\n});\napp.use(limiter);\n\n// Body parsing\napp.use(express.json({ limit: '1mb' }));\n\n// Health check\napp.get('/health', (req, res) => {\n  res.json({\n    status: 'healthy',\n    timestamp: new Date().toISOString(),\n    uptime: process.uptime()\n  });\n});\n\n// API routes\napp.get('/api/hello', (req, res) => {\n  res.json({ message: 'Hello World!' });\n});\n\nconsole.log('Microservice configured successfully');",
  "packages": ["express", "cors", "helmet", "express-rate-limit"],
  "files": {
    "package.json": "{\"type\": \"module\", \"name\": \"microservice\", \"version\": \"1.0.0\"}"
  }
}
```

## Troubleshooting

### Common Issues

1. **Module Resolution Issues**
   ```javascript
   // Check module paths
   console.log('Module paths:', module.paths);
   console.log('Current directory:', process.cwd());
   console.log('Node version:', process.version);
   ```

2. **Memory Issues**
   ```javascript
   // Monitor memory usage
   setInterval(() => {
     const usage = process.memoryUsage();
     console.log('Memory usage:', {
       rss: `${Math.round(usage.rss / 1024 / 1024)}MB`,
       heapUsed: `${Math.round(usage.heapUsed / 1024 / 1024)}MB`
     });
   }, 5000);
   ```

3. **Async/Await Issues**
   ```javascript
   // Proper async function usage
   async function main() {
     try {
       await someAsyncOperation();
     } catch (error) {
       console.error('Async error:', error);
       process.exit(1);
     }
   }
   
   main(); // Don't forget to call it!
   ```

4. **Package Installation Issues**
   ```bash
   # Clear npm cache if packages fail to install
   npm cache clean --force
   ```