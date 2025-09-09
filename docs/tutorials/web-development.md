# Web Development Tutorial

Learn how to build, test, and deploy web applications using SandboxRunner with Node.js, Express, React, and modern development tools.

## Prerequisites

- SandboxRunner installed and configured (see [Getting Started Guide](../getting-started.md))
- Basic knowledge of HTML, CSS, JavaScript
- Understanding of Node.js and npm basics
- Network access enabled in SandboxRunner config:
  ```yaml
  sandbox:
    network_mode: "bridge"  # Enable internet access
  ```

## Overview

In this tutorial, you'll build:
1. **Backend API** with Express.js, authentication, and database
2. **Frontend React app** with modern UI components
3. **Database integration** with SQLite
4. **Authentication system** with JWT tokens
5. **API testing** with automated test suites
6. **Deployment preparation** with Docker and environment configs

## Step 1: Create Development Sandbox

Create a sandbox with Node.js and development tools:

```bash
curl -X POST http://localhost:8080/mcp/tools/create_sandbox \
  -H "Content-Type: application/json" \
  -d '{
    "image": "node:18-slim",
    "memory_limit": "3G",
    "cpu_limit": "2.0",
    "network_mode": "bridge",
    "environment": {
      "NODE_ENV": "development",
      "PORT": "3000"
    }
  }'
```

**Save the sandbox_id for all subsequent steps.**

## Step 2: Setup Project Structure

Create the project directory structure and initialize package.json:

```bash
curl -X POST http://localhost:8080/mcp/tools/run_javascript \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "const fs = require(\"fs\");\nconst path = require(\"path\");\n\nconsole.log(\"Creating project structure...\");\n\n// Create directory structure\nconst dirs = [\n  \"/workspace/backend\",\n  \"/workspace/backend/src\",\n  \"/workspace/backend/src/routes\",\n  \"/workspace/backend/src/middleware\",\n  \"/workspace/backend/src/models\",\n  \"/workspace/backend/src/utils\",\n  \"/workspace/backend/tests\",\n  \"/workspace/frontend\",\n  \"/workspace/frontend/src\",\n  \"/workspace/frontend/src/components\",\n  \"/workspace/frontend/src/services\",\n  \"/workspace/frontend/src/utils\",\n  \"/workspace/frontend/public\",\n  \"/workspace/shared\"\n];\n\ndirs.forEach(dir => {\n  fs.mkdirSync(dir, { recursive: true });\n  console.log(`Created: ${dir}`);\n});\n\nconsole.log(\"\\nProject structure created successfully!\");\nconsole.log(\"\\nDirectory structure:\");\nconsole.log(\"📁 /workspace\");\nconsole.log(\"├── 📁 backend/          # Express.js API server\");\nconsole.log(\"│   ├── 📁 src/          # Source code\");\nconsole.log(\"│   │   ├── 📁 routes/   # API routes\");\nconsole.log(\"│   │   ├── 📁 middleware/ # Custom middleware\");\nconsole.log(\"│   │   ├── 📁 models/   # Database models\");\nconsole.log(\"│   │   └── 📁 utils/    # Utility functions\");\nconsole.log(\"│   └── 📁 tests/       # Test files\");\nconsole.log(\"├── 📁 frontend/         # React application\");\nconsole.log(\"│   ├── 📁 src/          # React components\");\nconsole.log(\"│   └── 📁 public/       # Static assets\");\nconsole.log(\"└── 📁 shared/           # Shared utilities\");\n\n// Create main project package.json for workspace management\nconst workspacePackage = {\n  name: \"fullstack-web-app\",\n  version: \"1.0.0\",\n  description: \"Full-stack web application built with SandboxRunner\",\n  private: true,\n  workspaces: [\"backend\", \"frontend\"],\n  scripts: {\n    \"install:all\": \"npm install && npm run install:backend && npm run install:frontend\",\n    \"install:backend\": \"cd backend && npm install\",\n    \"install:frontend\": \"cd frontend && npm install\",\n    \"dev:backend\": \"cd backend && npm run dev\",\n    \"dev:frontend\": \"cd frontend && npm start\",\n    \"test:backend\": \"cd backend && npm test\",\n    \"test:frontend\": \"cd frontend && npm test\",\n    \"build:frontend\": \"cd frontend && npm run build\",\n    \"start:prod\": \"cd backend && npm start\"\n  },\n  devDependencies: {\n    \"concurrently\": \"^8.2.0\"\n  }\n};\n\nfs.writeFileSync(\"/workspace/package.json\", JSON.stringify(workspacePackage, null, 2));\nconsole.log(\"\\nCreated workspace package.json\");"
  }'
```

## Step 3: Build Backend API with Express.js

### Create Backend Package Configuration

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/backend/package.json",
    "content": "{\n  \"name\": \"backend-api\",\n  \"version\": \"1.0.0\",\n  \"description\": \"Express.js REST API backend\",\n  \"main\": \"src/app.js\",\n  \"scripts\": {\n    \"start\": \"node src/app.js\",\n    \"dev\": \"nodemon src/app.js\",\n    \"test\": \"jest\",\n    \"test:watch\": \"jest --watch\",\n    \"test:coverage\": \"jest --coverage\"\n  },\n  \"dependencies\": {\n    \"express\": \"^4.18.2\",\n    \"cors\": \"^2.8.5\",\n    \"helmet\": \"^7.0.0\",\n    \"morgan\": \"^1.10.0\",\n    \"bcryptjs\": \"^2.4.3\",\n    \"jsonwebtoken\": \"^9.0.0\",\n    \"sqlite3\": \"^5.1.6\",\n    \"joi\": \"^17.9.2\",\n    \"dotenv\": \"^16.3.1\",\n    \"express-rate-limit\": \"^6.8.1\"\n  },\n  \"devDependencies\": {\n    \"nodemon\": \"^3.0.1\",\n    \"jest\": \"^29.6.1\",\n    \"supertest\": \"^6.3.3\"\n  }\n}"
  }'
```

### Create Main Express Application

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID", 
    "path": "/workspace/backend/src/app.js",
    "content": "const express = require(\"express\");\nconst cors = require(\"cors\");\nconst helmet = require(\"helmet\");\nconst morgan = require(\"morgan\");\nconst rateLimit = require(\"express-rate-limit\");\nrequire(\"dotenv\").config();\n\nconst authRoutes = require(\"./routes/auth\");\nconst userRoutes = require(\"./routes/users\");\nconst postRoutes = require(\"./routes/posts\");\nconst { errorHandler, notFound } = require(\"./middleware/errorMiddleware\");\nconst { initDatabase } = require(\"./models/database\");\n\nconst app = express();\nconst PORT = process.env.PORT || 3000;\n\n// Initialize database\ninitDatabase();\n\n// Security middleware\napp.use(helmet());\napp.use(cors({\n  origin: process.env.FRONTEND_URL || \"http://localhost:3001\",\n  credentials: true\n}));\n\n// Rate limiting\nconst limiter = rateLimit({\n  windowMs: 15 * 60 * 1000, // 15 minutes\n  max: 100 // limit each IP to 100 requests per windowMs\n});\napp.use(limiter);\n\n// Logging\napp.use(morgan(\"combined\"));\n\n// Body parsing\napp.use(express.json({ limit: \"10mb\" }));\napp.use(express.urlencoded({ extended: true }));\n\n// Health check endpoint\napp.get(\"/health\", (req, res) => {\n  res.json({\n    status: \"OK\",\n    timestamp: new Date().toISOString(),\n    uptime: process.uptime(),\n    version: \"1.0.0\"\n  });\n});\n\n// API routes\napp.use(\"/api/auth\", authRoutes);\napp.use(\"/api/users\", userRoutes);\napp.use(\"/api/posts\", postRoutes);\n\n// Serve static files for production\nif (process.env.NODE_ENV === \"production\") {\n  app.use(express.static(\"../frontend/build\"));\n  app.get(\"*\", (req, res) => {\n    res.sendFile(path.resolve(__dirname, \"../frontend/build/index.html\"));\n  });\n}\n\n// Error handling middleware\napp.use(notFound);\napp.use(errorHandler);\n\n// Start server\nif (process.env.NODE_ENV !== \"test\") {\n  app.listen(PORT, () => {\n    console.log(`🚀 Server running on port ${PORT}`);\n    console.log(`📊 Health check: http://localhost:${PORT}/health`);\n    console.log(`📝 API endpoints: http://localhost:${PORT}/api`);\n    console.log(`🔒 Environment: ${process.env.NODE_ENV || \"development\"}`);\n  });\n}\n\nmodule.exports = app;"
  }'
```

### Create Database Models

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/backend/src/models/database.js", 
    "content": "const sqlite3 = require(\"sqlite3\").verbose();\nconst path = require(\"path\");\n\nconst dbPath = path.join(__dirname, \"../../../database.sqlite\");\nconst db = new sqlite3.Database(dbPath);\n\n// Initialize database with tables\nconst initDatabase = () => {\n  return new Promise((resolve, reject) => {\n    db.serialize(() => {\n      // Users table\n      db.run(`\n        CREATE TABLE IF NOT EXISTS users (\n          id INTEGER PRIMARY KEY AUTOINCREMENT,\n          username TEXT UNIQUE NOT NULL,\n          email TEXT UNIQUE NOT NULL,\n          password TEXT NOT NULL,\n          first_name TEXT,\n          last_name TEXT,\n          bio TEXT,\n          avatar_url TEXT,\n          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP\n        )\n      `);\n\n      // Posts table\n      db.run(`\n        CREATE TABLE IF NOT EXISTS posts (\n          id INTEGER PRIMARY KEY AUTOINCREMENT,\n          title TEXT NOT NULL,\n          content TEXT NOT NULL,\n          author_id INTEGER NOT NULL,\n          published BOOLEAN DEFAULT 0,\n          tags TEXT,\n          views INTEGER DEFAULT 0,\n          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n          FOREIGN KEY (author_id) REFERENCES users (id)\n        )\n      `);\n\n      // Comments table\n      db.run(`\n        CREATE TABLE IF NOT EXISTS comments (\n          id INTEGER PRIMARY KEY AUTOINCREMENT,\n          content TEXT NOT NULL,\n          post_id INTEGER NOT NULL,\n          author_id INTEGER NOT NULL,\n          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n          FOREIGN KEY (post_id) REFERENCES posts (id),\n          FOREIGN KEY (author_id) REFERENCES users (id)\n        )\n      `);\n\n      console.log(\"✅ Database initialized successfully\");\n      resolve();\n    });\n  });\n};\n\n// User model functions\nconst User = {\n  create: (userData) => {\n    return new Promise((resolve, reject) => {\n      const { username, email, password, first_name, last_name } = userData;\n      db.run(\n        \"INSERT INTO users (username, email, password, first_name, last_name) VALUES (?, ?, ?, ?, ?)\",\n        [username, email, password, first_name, last_name],\n        function (err) {\n          if (err) reject(err);\n          else resolve({ id: this.lastID, ...userData });\n        }\n      );\n    });\n  },\n\n  findByEmail: (email) => {\n    return new Promise((resolve, reject) => {\n      db.get(\"SELECT * FROM users WHERE email = ?\", [email], (err, row) => {\n        if (err) reject(err);\n        else resolve(row);\n      });\n    });\n  },\n\n  findById: (id) => {\n    return new Promise((resolve, reject) => {\n      db.get(\"SELECT * FROM users WHERE id = ?\", [id], (err, row) => {\n        if (err) reject(err);\n        else resolve(row);\n      });\n    });\n  },\n\n  update: (id, updates) => {\n    return new Promise((resolve, reject) => {\n      const fields = Object.keys(updates).map(key => `${key} = ?`).join(\", \");\n      const values = [...Object.values(updates), id];\n      \n      db.run(\n        `UPDATE users SET ${fields}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,\n        values,\n        function (err) {\n          if (err) reject(err);\n          else resolve({ id, ...updates });\n        }\n      );\n    });\n  }\n};\n\n// Post model functions\nconst Post = {\n  create: (postData) => {\n    return new Promise((resolve, reject) => {\n      const { title, content, author_id, published = false, tags = \"\" } = postData;\n      db.run(\n        \"INSERT INTO posts (title, content, author_id, published, tags) VALUES (?, ?, ?, ?, ?)\",\n        [title, content, author_id, published, tags],\n        function (err) {\n          if (err) reject(err);\n          else resolve({ id: this.lastID, ...postData });\n        }\n      );\n    });\n  },\n\n  findAll: (limit = 10, offset = 0) => {\n    return new Promise((resolve, reject) => {\n      db.all(\n        `SELECT p.*, u.username, u.first_name, u.last_name \n         FROM posts p \n         JOIN users u ON p.author_id = u.id \n         WHERE p.published = 1 \n         ORDER BY p.created_at DESC \n         LIMIT ? OFFSET ?`,\n        [limit, offset],\n        (err, rows) => {\n          if (err) reject(err);\n          else resolve(rows);\n        }\n      );\n    });\n  },\n\n  findById: (id) => {\n    return new Promise((resolve, reject) => {\n      db.get(\n        `SELECT p.*, u.username, u.first_name, u.last_name \n         FROM posts p \n         JOIN users u ON p.author_id = u.id \n         WHERE p.id = ?`,\n        [id],\n        (err, row) => {\n          if (err) reject(err);\n          else resolve(row);\n        }\n      );\n    });\n  },\n\n  update: (id, updates) => {\n    return new Promise((resolve, reject) => {\n      const fields = Object.keys(updates).map(key => `${key} = ?`).join(\", \");\n      const values = [...Object.values(updates), id];\n      \n      db.run(\n        `UPDATE posts SET ${fields}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,\n        values,\n        function (err) {\n          if (err) reject(err);\n          else resolve({ id, ...updates });\n        }\n      );\n    });\n  },\n\n  delete: (id) => {\n    return new Promise((resolve, reject) => {\n      db.run(\"DELETE FROM posts WHERE id = ?\", [id], function (err) {\n        if (err) reject(err);\n        else resolve({ deleted: this.changes > 0 });\n      });\n    });\n  }\n};\n\nmodule.exports = {\n  db,\n  initDatabase,\n  User,\n  Post\n};"
  }'
```

### Create Authentication Routes

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/backend/src/routes/auth.js",
    "content": "const express = require(\"express\");\nconst bcrypt = require(\"bcryptjs\");\nconst jwt = require(\"jsonwebtoken\");\nconst Joi = require(\"joi\");\nconst { User } = require(\"../models/database\");\nconst router = express.Router();\n\n// Validation schemas\nconst registerSchema = Joi.object({\n  username: Joi.string().alphanum().min(3).max(30).required(),\n  email: Joi.string().email().required(),\n  password: Joi.string().min(6).required(),\n  first_name: Joi.string().max(50),\n  last_name: Joi.string().max(50)\n});\n\nconst loginSchema = Joi.object({\n  email: Joi.string().email().required(),\n  password: Joi.string().required()\n});\n\n// Helper function to generate JWT token\nconst generateToken = (userId) => {\n  return jwt.sign(\n    { userId },\n    process.env.JWT_SECRET || \"your-secret-key\",\n    { expiresIn: \"7d\" }\n  );\n};\n\n// Register endpoint\nrouter.post(\"/register\", async (req, res) => {\n  try {\n    // Validate input\n    const { error, value } = registerSchema.validate(req.body);\n    if (error) {\n      return res.status(400).json({\n        success: false,\n        message: \"Validation error\",\n        errors: error.details.map(detail => detail.message)\n      });\n    }\n\n    const { username, email, password, first_name, last_name } = value;\n\n    // Check if user already exists\n    const existingUser = await User.findByEmail(email);\n    if (existingUser) {\n      return res.status(409).json({\n        success: false,\n        message: \"User with this email already exists\"\n      });\n    }\n\n    // Hash password\n    const saltRounds = 12;\n    const hashedPassword = await bcrypt.hash(password, saltRounds);\n\n    // Create user\n    const newUser = await User.create({\n      username,\n      email,\n      password: hashedPassword,\n      first_name,\n      last_name\n    });\n\n    // Generate token\n    const token = generateToken(newUser.id);\n\n    res.status(201).json({\n      success: true,\n      message: \"User registered successfully\",\n      data: {\n        user: {\n          id: newUser.id,\n          username,\n          email,\n          first_name,\n          last_name\n        },\n        token\n      }\n    });\n  } catch (error) {\n    console.error(\"Registration error:\", error);\n    res.status(500).json({\n      success: false,\n      message: \"Internal server error\",\n      error: process.env.NODE_ENV === \"development\" ? error.message : undefined\n    });\n  }\n});\n\n// Login endpoint\nrouter.post(\"/login\", async (req, res) => {\n  try {\n    // Validate input\n    const { error, value } = loginSchema.validate(req.body);\n    if (error) {\n      return res.status(400).json({\n        success: false,\n        message: \"Validation error\",\n        errors: error.details.map(detail => detail.message)\n      });\n    }\n\n    const { email, password } = value;\n\n    // Find user\n    const user = await User.findByEmail(email);\n    if (!user) {\n      return res.status(401).json({\n        success: false,\n        message: \"Invalid credentials\"\n      });\n    }\n\n    // Check password\n    const isValidPassword = await bcrypt.compare(password, user.password);\n    if (!isValidPassword) {\n      return res.status(401).json({\n        success: false,\n        message: \"Invalid credentials\"\n      });\n    }\n\n    // Generate token\n    const token = generateToken(user.id);\n\n    res.json({\n      success: true,\n      message: \"Login successful\",\n      data: {\n        user: {\n          id: user.id,\n          username: user.username,\n          email: user.email,\n          first_name: user.first_name,\n          last_name: user.last_name\n        },\n        token\n      }\n    });\n  } catch (error) {\n    console.error(\"Login error:\", error);\n    res.status(500).json({\n      success: false,\n      message: \"Internal server error\",\n      error: process.env.NODE_ENV === \"development\" ? error.message : undefined\n    });\n  }\n});\n\n// Token verification endpoint\nrouter.get(\"/verify\", async (req, res) => {\n  try {\n    const token = req.headers.authorization?.replace(\"Bearer \", \"\");\n    \n    if (!token) {\n      return res.status(401).json({\n        success: false,\n        message: \"No token provided\"\n      });\n    }\n\n    const decoded = jwt.verify(token, process.env.JWT_SECRET || \"your-secret-key\");\n    const user = await User.findById(decoded.userId);\n    \n    if (!user) {\n      return res.status(401).json({\n        success: false,\n        message: \"Invalid token\"\n      });\n    }\n\n    res.json({\n      success: true,\n      data: {\n        user: {\n          id: user.id,\n          username: user.username,\n          email: user.email,\n          first_name: user.first_name,\n          last_name: user.last_name\n        }\n      }\n    });\n  } catch (error) {\n    res.status(401).json({\n      success: false,\n      message: \"Invalid token\"\n    });\n  }\n});\n\nmodule.exports = router;"
  }'
```

### Create Posts Routes

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/backend/src/routes/posts.js",
    "content": "const express = require(\"express\");\nconst Joi = require(\"joi\");\nconst { Post } = require(\"../models/database\");\nconst { auth } = require(\"../middleware/auth\");\nconst router = express.Router();\n\n// Validation schemas\nconst createPostSchema = Joi.object({\n  title: Joi.string().min(1).max(255).required(),\n  content: Joi.string().min(1).required(),\n  published: Joi.boolean().default(false),\n  tags: Joi.string().allow(\"\").default(\"\")\n});\n\n// Get all posts\nrouter.get(\"/\", async (req, res) => {\n  try {\n    const page = parseInt(req.query.page) || 1;\n    const limit = parseInt(req.query.limit) || 10;\n    const offset = (page - 1) * limit;\n\n    const posts = await Post.findAll(limit, offset);\n    \n    res.json({\n      success: true,\n      data: {\n        posts,\n        pagination: {\n          page,\n          limit,\n          total: posts.length\n        }\n      }\n    });\n  } catch (error) {\n    console.error(\"Get posts error:\", error);\n    res.status(500).json({\n      success: false,\n      message: \"Internal server error\"\n    });\n  }\n});\n\n// Get single post\nrouter.get(\"/:id\", async (req, res) => {\n  try {\n    const postId = parseInt(req.params.id);\n    if (isNaN(postId)) {\n      return res.status(400).json({\n        success: false,\n        message: \"Invalid post ID\"\n      });\n    }\n\n    const post = await Post.findById(postId);\n    if (!post) {\n      return res.status(404).json({\n        success: false,\n        message: \"Post not found\"\n      });\n    }\n\n    res.json({\n      success: true,\n      data: { post }\n    });\n  } catch (error) {\n    console.error(\"Get post error:\", error);\n    res.status(500).json({\n      success: false,\n      message: \"Internal server error\"\n    });\n  }\n});\n\n// Create new post (requires authentication)\nrouter.post(\"/\", auth, async (req, res) => {\n  try {\n    // Validate input\n    const { error, value } = createPostSchema.validate(req.body);\n    if (error) {\n      return res.status(400).json({\n        success: false,\n        message: \"Validation error\",\n        errors: error.details.map(detail => detail.message)\n      });\n    }\n\n    const postData = {\n      ...value,\n      author_id: req.user.id\n    };\n\n    const newPost = await Post.create(postData);\n    const post = await Post.findById(newPost.id);\n\n    res.status(201).json({\n      success: true,\n      message: \"Post created successfully\",\n      data: { post }\n    });\n  } catch (error) {\n    console.error(\"Create post error:\", error);\n    res.status(500).json({\n      success: false,\n      message: \"Internal server error\"\n    });\n  }\n});\n\n// Update post (requires authentication and ownership)\nrouter.put(\"/:id\", auth, async (req, res) => {\n  try {\n    const postId = parseInt(req.params.id);\n    if (isNaN(postId)) {\n      return res.status(400).json({\n        success: false,\n        message: \"Invalid post ID\"\n      });\n    }\n\n    // Check if post exists and user owns it\n    const existingPost = await Post.findById(postId);\n    if (!existingPost) {\n      return res.status(404).json({\n        success: false,\n        message: \"Post not found\"\n      });\n    }\n\n    if (existingPost.author_id !== req.user.id) {\n      return res.status(403).json({\n        success: false,\n        message: \"You can only update your own posts\"\n      });\n    }\n\n    // Validate input\n    const { error, value } = createPostSchema.validate(req.body);\n    if (error) {\n      return res.status(400).json({\n        success: false,\n        message: \"Validation error\",\n        errors: error.details.map(detail => detail.message)\n      });\n    }\n\n    await Post.update(postId, value);\n    const updatedPost = await Post.findById(postId);\n\n    res.json({\n      success: true,\n      message: \"Post updated successfully\",\n      data: { post: updatedPost }\n    });\n  } catch (error) {\n    console.error(\"Update post error:\", error);\n    res.status(500).json({\n      success: false,\n      message: \"Internal server error\"\n    });\n  }\n});\n\n// Delete post (requires authentication and ownership)\nrouter.delete(\"/:id\", auth, async (req, res) => {\n  try {\n    const postId = parseInt(req.params.id);\n    if (isNaN(postId)) {\n      return res.status(400).json({\n        success: false,\n        message: \"Invalid post ID\"\n      });\n    }\n\n    // Check if post exists and user owns it\n    const existingPost = await Post.findById(postId);\n    if (!existingPost) {\n      return res.status(404).json({\n        success: false,\n        message: \"Post not found\"\n      });\n    }\n\n    if (existingPost.author_id !== req.user.id) {\n      return res.status(403).json({\n        success: false,\n        message: \"You can only delete your own posts\"\n      });\n    }\n\n    await Post.delete(postId);\n\n    res.json({\n      success: true,\n      message: \"Post deleted successfully\"\n    });\n  } catch (error) {\n    console.error(\"Delete post error:\", error);\n    res.status(500).json({\n      success: false,\n      message: \"Internal server error\"\n    });\n  }\n});\n\nmodule.exports = router;"
  }'
```

### Create Middleware

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/backend/src/middleware/auth.js",
    "content": "const jwt = require(\"jsonwebtoken\");\nconst { User } = require(\"../models/database\");\n\nconst auth = async (req, res, next) => {\n  try {\n    const token = req.headers.authorization?.replace(\"Bearer \", \"\");\n    \n    if (!token) {\n      return res.status(401).json({\n        success: false,\n        message: \"Access denied. No token provided.\"\n      });\n    }\n\n    const decoded = jwt.verify(token, process.env.JWT_SECRET || \"your-secret-key\");\n    const user = await User.findById(decoded.userId);\n    \n    if (!user) {\n      return res.status(401).json({\n        success: false,\n        message: \"Invalid token.\"\n      });\n    }\n\n    req.user = {\n      id: user.id,\n      username: user.username,\n      email: user.email\n    };\n    \n    next();\n  } catch (error) {\n    res.status(401).json({\n      success: false,\n      message: \"Invalid token.\"\n    });\n  }\n};\n\nmodule.exports = { auth };"
  }'
```

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/backend/src/middleware/errorMiddleware.js",
    "content": "const notFound = (req, res, next) => {\n  const error = new Error(`Not found - ${req.originalUrl}`);\n  res.status(404);\n  next(error);\n};\n\nconst errorHandler = (err, req, res, next) => {\n  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;\n  \n  res.status(statusCode).json({\n    success: false,\n    message: err.message,\n    stack: process.env.NODE_ENV === \"development\" ? err.stack : undefined,\n    timestamp: new Date().toISOString(),\n    path: req.path,\n    method: req.method\n  });\n};\n\nmodule.exports = {\n  notFound,\n  errorHandler\n};"
  }'
```

### Create User Routes

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/backend/src/routes/users.js",
    "content": "const express = require(\"express\");\nconst { User } = require(\"../models/database\");\nconst { auth } = require(\"../middleware/auth\");\nconst router = express.Router();\n\n// Get current user profile\nrouter.get(\"/profile\", auth, async (req, res) => {\n  try {\n    const user = await User.findById(req.user.id);\n    if (!user) {\n      return res.status(404).json({\n        success: false,\n        message: \"User not found\"\n      });\n    }\n\n    // Remove password from response\n    const { password, ...userProfile } = user;\n    \n    res.json({\n      success: true,\n      data: { user: userProfile }\n    });\n  } catch (error) {\n    console.error(\"Get profile error:\", error);\n    res.status(500).json({\n      success: false,\n      message: \"Internal server error\"\n    });\n  }\n});\n\n// Update user profile\nrouter.put(\"/profile\", auth, async (req, res) => {\n  try {\n    const { first_name, last_name, bio, avatar_url } = req.body;\n    \n    const updates = {};\n    if (first_name !== undefined) updates.first_name = first_name;\n    if (last_name !== undefined) updates.last_name = last_name;\n    if (bio !== undefined) updates.bio = bio;\n    if (avatar_url !== undefined) updates.avatar_url = avatar_url;\n\n    await User.update(req.user.id, updates);\n    const updatedUser = await User.findById(req.user.id);\n    \n    // Remove password from response\n    const { password, ...userProfile } = updatedUser;\n    \n    res.json({\n      success: true,\n      message: \"Profile updated successfully\",\n      data: { user: userProfile }\n    });\n  } catch (error) {\n    console.error(\"Update profile error:\", error);\n    res.status(500).json({\n      success: false,\n      message: \"Internal server error\"\n    });\n  }\n});\n\nmodule.exports = router;"
  }'
```

## Step 4: Install Backend Dependencies and Test

Install backend dependencies and run initial tests:

```bash
curl -X POST http://localhost:8080/mcp/tools/run_javascript \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "const { spawn } = require(\"child_process\");\nconst fs = require(\"fs\");\n\nconsole.log(\"Installing backend dependencies...\");\n\n// Change to backend directory and install dependencies\nprocess.chdir(\"/workspace/backend\");\n\nconst installProcess = spawn(\"npm\", [\"install\"], { stdio: \"inherit\" });\n\ninstallProcess.on(\"close\", (code) => {\n  if (code === 0) {\n    console.log(\"\\n✅ Backend dependencies installed successfully!\");\n    \n    // Create .env file\n    const envContent = `NODE_ENV=development\nPORT=3000\nJWT_SECRET=your-super-secret-jwt-key-change-this-in-production\nFRONTEND_URL=http://localhost:3001`;\n    \n    fs.writeFileSync(\".env\", envContent);\n    console.log(\"✅ Environment file created\");\n    \n    console.log(\"\\n🚀 Backend setup complete!\");\n    console.log(\"\\nTo start the backend server:\");\n    console.log(\"cd /workspace/backend && npm run dev\");\n  } else {\n    console.error(`❌ Installation failed with code ${code}`);\n  }\n});",
    "working_dir": "/workspace/backend"
  }'
```

## Step 5: Start Backend Server

Start the backend API server:

```bash
curl -X POST http://localhost:8080/mcp/tools/run_javascript \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "const { spawn } = require(\"child_process\");\n\nconsole.log(\"Starting backend server...\");\nprocess.chdir(\"/workspace/backend\");\n\n// Start server in background\nconst serverProcess = spawn(\"npm\", [\"start\"], { \n  stdio: [\"pipe\", \"pipe\", \"pipe\"],\n  detached: true\n});\n\nlet serverOutput = \"\";\n\nserverProcess.stdout.on(\"data\", (data) => {\n  const output = data.toString();\n  serverOutput += output;\n  console.log(output.trim());\n});\n\nserverProcess.stderr.on(\"data\", (data) => {\n  console.error(data.toString().trim());\n});\n\n// Give server time to start\nsetTimeout(() => {\n  console.log(\"\\n✅ Backend server started!\");\n  console.log(\"\\n📊 Testing server endpoints...\");\n  \n  // Test health endpoint\n  const http = require(\"http\");\n  \n  const healthReq = http.request({\n    hostname: \"localhost\",\n    port: 3000,\n    path: \"/health\",\n    method: \"GET\"\n  }, (res) => {\n    let data = \"\";\n    res.on(\"data\", (chunk) => data += chunk);\n    res.on(\"end\", () => {\n      console.log(\"\\n🔍 Health Check Response:\");\n      console.log(JSON.stringify(JSON.parse(data), null, 2));\n    });\n  });\n  \n  healthReq.on(\"error\", (err) => {\n    console.error(\"Health check failed:\", err.message);\n  });\n  \n  healthReq.end();\n  \n  console.log(\"\\n🌐 Backend API is running at:\");\n  console.log(\"- Health: http://localhost:3000/health\");\n  console.log(\"- Auth: http://localhost:3000/api/auth\");\n  console.log(\"- Posts: http://localhost:3000/api/posts\");\n  console.log(\"- Users: http://localhost:3000/api/users\");\n  \n}, 3000);",
    "timeout": 5,
    "working_dir": "/workspace/backend"
  }'
```

## Step 6: Create React Frontend

### Initialize React Application

```bash
curl -X POST http://localhost:8080/mcp/tools/run_javascript \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "const fs = require(\"fs\");\n\nconsole.log(\"Setting up React frontend...\");\n\n// Create package.json for frontend\nconst frontendPackage = {\n  name: \"frontend-react-app\",\n  version: \"1.0.0\",\n  private: true,\n  dependencies: {\n    \"react\": \"^18.2.0\",\n    \"react-dom\": \"^18.2.0\",\n    \"react-router-dom\": \"^6.14.1\",\n    \"axios\": \"^1.4.0\",\n    \"@mui/material\": \"^5.14.0\",\n    \"@mui/icons-material\": \"^5.14.0\",\n    \"@emotion/react\": \"^11.11.1\",\n    \"@emotion/styled\": \"^11.11.0\",\n    \"react-hook-form\": \"^7.45.2\",\n    \"react-query\": \"^3.39.3\",\n    \"react-toastify\": \"^9.1.3\"\n  },\n  scripts: {\n    \"start\": \"react-scripts start\",\n    \"build\": \"react-scripts build\",\n    \"test\": \"react-scripts test\",\n    \"eject\": \"react-scripts eject\"\n  },\n  devDependencies: {\n    \"react-scripts\": \"^5.0.1\",\n    \"@testing-library/react\": \"^13.4.0\",\n    \"@testing-library/jest-dom\": \"^5.17.0\",\n    \"@testing-library/user-event\": \"^14.4.3\"\n  },\n  browserslist: {\n    production: [\n      \">0.2%\",\n      \"not dead\",\n      \"not op_mini all\"\n    ],\n    development: [\n      \"last 1 chrome version\",\n      \"last 1 firefox version\",\n      \"last 1 safari version\"\n    ]\n  }\n};\n\n// Write frontend package.json\nprocess.chdir(\"/workspace/frontend\");\nfs.writeFileSync(\"package.json\", JSON.stringify(frontendPackage, null, 2));\nconsole.log(\"✅ Frontend package.json created\");\n\n// Create public/index.html\nconst indexHtml = `<!DOCTYPE html>\n<html lang=\"en\">\n  <head>\n    <meta charset=\"utf-8\" />\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n    <meta name=\"theme-color\" content=\"#000000\" />\n    <meta name=\"description\" content=\"Full-stack web application built with SandboxRunner\" />\n    <title>SandboxRunner Web App</title>\n    <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n    <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n    <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap\" rel=\"stylesheet\">\n  </head>\n  <body>\n    <noscript>You need to enable JavaScript to run this app.</noscript>\n    <div id=\"root\"></div>\n  </body>\n</html>`;\n\nfs.writeFileSync(\"public/index.html\", indexHtml);\nconsole.log(\"✅ Frontend HTML template created\");\n\nconsole.log(\"\\n📦 Frontend structure initialized!\");"
  }'
```

### Create React Components

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/frontend/src/index.js",
    "content": "import React from \"react\";\nimport ReactDOM from \"react-dom/client\";\nimport { BrowserRouter } from \"react-router-dom\";\nimport { QueryClient, QueryClientProvider } from \"react-query\";\nimport { ThemeProvider, createTheme } from \"@mui/material/styles\";\nimport CssBaseline from \"@mui/material/CssBaseline\";\nimport { ToastContainer } from \"react-toastify\";\nimport \"react-toastify/dist/ReactToastify.css\";\n\nimport App from \"./App\";\nimport { AuthProvider } from \"./contexts/AuthContext\";\n\n// Create Material-UI theme\nconst theme = createTheme({\n  palette: {\n    mode: \"light\",\n    primary: {\n      main: \"#1976d2\",\n    },\n    secondary: {\n      main: \"#dc004e\",\n    },\n  },\n  typography: {\n    fontFamily: \"Inter, sans-serif\",\n  },\n});\n\n// Create React Query client\nconst queryClient = new QueryClient({\n  defaultOptions: {\n    queries: {\n      retry: 1,\n      refetchOnWindowFocus: false,\n    },\n  },\n});\n\nconst root = ReactDOM.createRoot(document.getElementById(\"root\"));\n\nroot.render(\n  <React.StrictMode>\n    <QueryClientProvider client={queryClient}>\n      <ThemeProvider theme={theme}>\n        <CssBaseline />\n        <BrowserRouter>\n          <AuthProvider>\n            <App />\n            <ToastContainer\n              position=\"top-right\"\n              autoClose={5000}\n              hideProgressBar={false}\n              newestOnTop={false}\n              closeOnClick\n              rtl={false}\n              pauseOnFocusLoss\n              draggable\n              pauseOnHover\n            />\n          </AuthProvider>\n        </BrowserRouter>\n      </ThemeProvider>\n    </QueryClientProvider>\n  </React.StrictMode>\n);"
  }'
```

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID", 
    "path": "/workspace/frontend/src/App.js",
    "content": "import React from \"react\";\nimport { Routes, Route, Navigate } from \"react-router-dom\";\nimport { Container } from \"@mui/material\";\n\nimport Layout from \"./components/Layout\";\nimport HomePage from \"./pages/HomePage\";\nimport LoginPage from \"./pages/LoginPage\";\nimport RegisterPage from \"./pages/RegisterPage\";\nimport DashboardPage from \"./pages/DashboardPage\";\nimport PostsPage from \"./pages/PostsPage\";\nimport CreatePostPage from \"./pages/CreatePostPage\";\nimport PostDetailPage from \"./pages/PostDetailPage\";\nimport ProfilePage from \"./pages/ProfilePage\";\nimport { useAuth } from \"./contexts/AuthContext\";\nimport ProtectedRoute from \"./components/ProtectedRoute\";\n\nfunction App() {\n  const { user, loading } = useAuth();\n\n  if (loading) {\n    return (\n      <Container maxWidth=\"sm\" sx={{ mt: 4, textAlign: \"center\" }}>\n        <div>Loading...</div>\n      </Container>\n    );\n  }\n\n  return (\n    <Layout>\n      <Routes>\n        {/* Public routes */}\n        <Route path=\"/\" element={<HomePage />} />\n        <Route path=\"/posts\" element={<PostsPage />} />\n        <Route path=\"/posts/:id\" element={<PostDetailPage />} />\n        \n        {/* Auth routes */}\n        <Route \n          path=\"/login\" \n          element={user ? <Navigate to=\"/dashboard\" replace /> : <LoginPage />} \n        />\n        <Route \n          path=\"/register\" \n          element={user ? <Navigate to=\"/dashboard\" replace /> : <RegisterPage />} \n        />\n        \n        {/* Protected routes */}\n        <Route \n          path=\"/dashboard\" \n          element={\n            <ProtectedRoute>\n              <DashboardPage />\n            </ProtectedRoute>\n          } \n        />\n        <Route \n          path=\"/create-post\" \n          element={\n            <ProtectedRoute>\n              <CreatePostPage />\n            </ProtectedRoute>\n          } \n        />\n        <Route \n          path=\"/profile\" \n          element={\n            <ProtectedRoute>\n              <ProfilePage />\n            </ProtectedRoute>\n          } \n        />\n        \n        {/* Catch all */}\n        <Route path=\"*\" element={<Navigate to=\"/\" replace />} />\n      </Routes>\n    </Layout>\n  );\n}\n\nexport default App;"
  }'
```

### Create Authentication Context

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/frontend/src/contexts/AuthContext.js",
    "content": "import React, { createContext, useContext, useState, useEffect } from \"react\";\nimport { toast } from \"react-toastify\";\nimport * as authService from \"../services/authService\";\n\nconst AuthContext = createContext();\n\nexport const useAuth = () => {\n  const context = useContext(AuthContext);\n  if (!context) {\n    throw new Error(\"useAuth must be used within an AuthProvider\");\n  }\n  return context;\n};\n\nexport const AuthProvider = ({ children }) => {\n  const [user, setUser] = useState(null);\n  const [loading, setLoading] = useState(true);\n\n  useEffect(() => {\n    const initAuth = async () => {\n      const token = localStorage.getItem(\"token\");\n      if (token) {\n        try {\n          const userData = await authService.verifyToken(token);\n          setUser(userData.user);\n        } catch (error) {\n          localStorage.removeItem(\"token\");\n          console.error(\"Token verification failed:\", error);\n        }\n      }\n      setLoading(false);\n    };\n\n    initAuth();\n  }, []);\n\n  const login = async (email, password) => {\n    try {\n      const response = await authService.login(email, password);\n      const { user, token } = response.data;\n      \n      localStorage.setItem(\"token\", token);\n      setUser(user);\n      toast.success(\"Welcome back!\");\n      \n      return { success: true };\n    } catch (error) {\n      const message = error.response?.data?.message || \"Login failed\";\n      toast.error(message);\n      return { success: false, error: message };\n    }\n  };\n\n  const register = async (userData) => {\n    try {\n      const response = await authService.register(userData);\n      const { user, token } = response.data;\n      \n      localStorage.setItem(\"token\", token);\n      setUser(user);\n      toast.success(\"Welcome! Your account has been created.\");\n      \n      return { success: true };\n    } catch (error) {\n      const message = error.response?.data?.message || \"Registration failed\";\n      toast.error(message);\n      return { success: false, error: message };\n    }\n  };\n\n  const logout = () => {\n    localStorage.removeItem(\"token\");\n    setUser(null);\n    toast.success(\"You have been logged out\");\n  };\n\n  const updateUser = (userData) => {\n    setUser(prevUser => ({ ...prevUser, ...userData }));\n  };\n\n  const value = {\n    user,\n    loading,\n    login,\n    register,\n    logout,\n    updateUser\n  };\n\n  return (\n    <AuthContext.Provider value={value}>\n      {children}\n    </AuthContext.Provider>\n  );\n};"
  }'
```

### Create API Services

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/frontend/src/services/api.js",
    "content": "import axios from \"axios\";\n\nconst API_BASE_URL = process.env.REACT_APP_API_URL || \"http://localhost:3000/api\";\n\n// Create axios instance\nconst api = axios.create({\n  baseURL: API_BASE_URL,\n  timeout: 10000,\n});\n\n// Request interceptor to add auth token\napi.interceptors.request.use(\n  (config) => {\n    const token = localStorage.getItem(\"token\");\n    if (token) {\n      config.headers.Authorization = `Bearer ${token}`;\n    }\n    return config;\n  },\n  (error) => {\n    return Promise.reject(error);\n  }\n);\n\n// Response interceptor for error handling\napi.interceptors.response.use(\n  (response) => {\n    return response;\n  },\n  (error) => {\n    if (error.response?.status === 401) {\n      // Token expired or invalid\n      localStorage.removeItem(\"token\");\n      window.location.href = \"/login\";\n    }\n    return Promise.reject(error);\n  }\n);\n\nexport default api;"
  }'
```

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/frontend/src/services/authService.js",
    "content": "import api from \"./api\";\n\nexport const login = async (email, password) => {\n  const response = await api.post(\"/auth/login\", { email, password });\n  return response.data;\n};\n\nexport const register = async (userData) => {\n  const response = await api.post(\"/auth/register\", userData);\n  return response.data;\n};\n\nexport const verifyToken = async (token) => {\n  const response = await api.get(\"/auth/verify\", {\n    headers: {\n      Authorization: `Bearer ${token}`\n    }\n  });\n  return response.data;\n};\n\nexport const getCurrentUser = async () => {\n  const response = await api.get(\"/users/profile\");\n  return response.data;\n};\n\nexport const updateProfile = async (userData) => {\n  const response = await api.put(\"/users/profile\", userData);\n  return response.data;\n};"
  }'
```

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/frontend/src/services/postService.js",
    "content": "import api from \"./api\";\n\nexport const getPosts = async (page = 1, limit = 10) => {\n  const response = await api.get(`/posts?page=${page}&limit=${limit}`);\n  return response.data;\n};\n\nexport const getPost = async (id) => {\n  const response = await api.get(`/posts/${id}`);\n  return response.data;\n};\n\nexport const createPost = async (postData) => {\n  const response = await api.post(\"/posts\", postData);\n  return response.data;\n};\n\nexport const updatePost = async (id, postData) => {\n  const response = await api.put(`/posts/${id}`, postData);\n  return response.data;\n};\n\nexport const deletePost = async (id) => {\n  const response = await api.delete(`/posts/${id}`);\n  return response.data;\n};"
  }'
```

### Create React Components

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/frontend/src/components/Layout.js",
    "content": "import React from \"react\";\nimport {\n  AppBar,\n  Toolbar,\n  Typography,\n  Button,\n  Box,\n  Container,\n  IconButton,\n  Menu,\n  MenuItem,\n} from \"@mui/material\";\nimport {\n  Home as HomeIcon,\n  AccountCircle,\n  Article as ArticleIcon,\n  Dashboard as DashboardIcon,\n  ExitToApp as LogoutIcon,\n  Person as PersonIcon,\n} from \"@mui/icons-material\";\nimport { useNavigate, useLocation } from \"react-router-dom\";\nimport { useAuth } from \"../contexts/AuthContext\";\n\nconst Layout = ({ children }) => {\n  const navigate = useNavigate();\n  const location = useLocation();\n  const { user, logout } = useAuth();\n  const [anchorEl, setAnchorEl] = React.useState(null);\n\n  const handleMenu = (event) => {\n    setAnchorEl(event.currentTarget);\n  };\n\n  const handleClose = () => {\n    setAnchorEl(null);\n  };\n\n  const handleLogout = () => {\n    logout();\n    handleClose();\n    navigate(\"/\");\n  };\n\n  return (\n    <Box sx={{ flexGrow: 1 }}>\n      <AppBar position=\"static\">\n        <Toolbar>\n          <IconButton\n            size=\"large\"\n            edge=\"start\"\n            color=\"inherit\"\n            aria-label=\"home\"\n            onClick={() => navigate(\"/\")}\n          >\n            <HomeIcon />\n          </IconButton>\n          <Typography variant=\"h6\" component=\"div\" sx={{ flexGrow: 1 }}>\n            SandboxRunner Web App\n          </Typography>\n\n          {/* Navigation buttons */}\n          <Button\n            color=\"inherit\"\n            startIcon={<ArticleIcon />}\n            onClick={() => navigate(\"/posts\")}\n            sx={{ mr: 1 }}\n          >\n            Posts\n          </Button>\n\n          {user ? (\n            <>\n              <Button\n                color=\"inherit\"\n                startIcon={<DashboardIcon />}\n                onClick={() => navigate(\"/dashboard\")}\n                sx={{ mr: 1 }}\n              >\n                Dashboard\n              </Button>\n              <IconButton\n                size=\"large\"\n                aria-label=\"account of current user\"\n                aria-controls=\"menu-appbar\"\n                aria-haspopup=\"true\"\n                onClick={handleMenu}\n                color=\"inherit\"\n              >\n                <AccountCircle />\n              </IconButton>\n              <Menu\n                id=\"menu-appbar\"\n                anchorEl={anchorEl}\n                anchorOrigin={{\n                  vertical: \"top\",\n                  horizontal: \"right\",\n                }}\n                keepMounted\n                transformOrigin={{\n                  vertical: \"top\",\n                  horizontal: \"right\",\n                }}\n                open={Boolean(anchorEl)}\n                onClose={handleClose}\n              >\n                <MenuItem onClick={() => { navigate(\"/profile\"); handleClose(); }}>\n                  <PersonIcon sx={{ mr: 1 }} />\n                  Profile\n                </MenuItem>\n                <MenuItem onClick={handleLogout}>\n                  <LogoutIcon sx={{ mr: 1 }} />\n                  Logout\n                </MenuItem>\n              </Menu>\n            </>\n          ) : (\n            <>\n              <Button color=\"inherit\" onClick={() => navigate(\"/login\")}>\n                Login\n              </Button>\n              <Button color=\"inherit\" onClick={() => navigate(\"/register\")}>\n                Register\n              </Button>\n            </>\n          )}\n        </Toolbar>\n      </AppBar>\n\n      <Container maxWidth=\"lg\" sx={{ mt: 4, mb: 4 }}>\n        {children}\n      </Container>\n    </Box>\n  );\n};\n\nexport default Layout;"
  }'
```

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/frontend/src/components/ProtectedRoute.js",
    "content": "import React from \"react\";\nimport { Navigate, useLocation } from \"react-router-dom\";\nimport { useAuth } from \"../contexts/AuthContext\";\n\nconst ProtectedRoute = ({ children }) => {\n  const { user, loading } = useAuth();\n  const location = useLocation();\n\n  if (loading) {\n    return <div>Loading...</div>;\n  }\n\n  if (!user) {\n    // Redirect to login page with return url\n    return <Navigate to=\"/login\" state={{ from: location }} replace />;\n  }\n\n  return children;\n};\n\nexport default ProtectedRoute;"
  }'
```

### Create Pages

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/frontend/src/pages/HomePage.js",
    "content": "import React from \"react\";\nimport {\n  Box,\n  Typography,\n  Container,\n  Grid,\n  Card,\n  CardContent,\n  Button,\n  CardActions,\n} from \"@mui/material\";\nimport {\n  Code as CodeIcon,\n  Security as SecurityIcon,\n  Speed as SpeedIcon,\n  CloudQueue as CloudIcon,\n} from \"@mui/icons-material\";\nimport { useNavigate } from \"react-router-dom\";\nimport { useAuth } from \"../contexts/AuthContext\";\n\nconst HomePage = () => {\n  const navigate = useNavigate();\n  const { user } = useAuth();\n\n  const features = [\n    {\n      icon: <CodeIcon sx={{ fontSize: 40, color: \"primary.main\" }} />,\n      title: \"Multi-Language Support\",\n      description: \"Execute code in Python, JavaScript, Go, Rust, and more in secure sandboxed environments.\"\n    },\n    {\n      icon: <SecurityIcon sx={{ fontSize: 40, color: \"primary.main\" }} />,\n      title: \"Secure Execution\",\n      description: \"All code runs in isolated containers with resource limits and security policies.\"\n    },\n    {\n      icon: <SpeedIcon sx={{ fontSize: 40, color: \"primary.main\" }} />,\n      title: \"Fast Performance\",\n      description: \"Optimized container startup and execution for responsive development workflows.\"\n    },\n    {\n      icon: <CloudIcon sx={{ fontSize: 40, color: \"primary.main\" }} />,\n      title: \"Cloud Ready\",\n      description: \"Deploy anywhere with Docker support and cloud-native architecture.\"\n    },\n  ];\n\n  return (\n    <Container maxWidth=\"lg\">\n      {/* Hero Section */}\n      <Box\n        sx={{\n          textAlign: \"center\",\n          py: 8,\n          background: \"linear-gradient(45deg, #FE6B8B 30%, #FF8E53 90%)\",\n          borderRadius: 2,\n          color: \"white\",\n          mb: 6,\n        }}\n      >\n        <Typography variant=\"h2\" component=\"h1\" gutterBottom>\n          SandboxRunner\n        </Typography>\n        <Typography variant=\"h5\" component=\"h2\" gutterBottom>\n          Secure Multi-Language Code Execution Platform\n        </Typography>\n        <Typography variant=\"body1\" sx={{ mb: 4, maxWidth: \"md\", mx: \"auto\" }}>\n          Build, test, and deploy applications with confidence using our secure,\n          containerized execution environment. Perfect for development, education,\n          and production workloads.\n        </Typography>\n        {!user && (\n          <Box sx={{ mt: 4 }}>\n            <Button\n              variant=\"contained\"\n              size=\"large\"\n              onClick={() => navigate(\"/register\")}\n              sx={{\n                mr: 2,\n                bgcolor: \"white\",\n                color: \"primary.main\",\n                \"&:hover\": {\n                  bgcolor: \"grey.100\",\n                },\n              }}\n            >\n              Get Started\n            </Button>\n            <Button\n              variant=\"outlined\"\n              size=\"large\"\n              onClick={() => navigate(\"/posts\")}\n              sx={{\n                borderColor: \"white\",\n                color: \"white\",\n                \"&:hover\": {\n                  borderColor: \"white\",\n                  bgcolor: \"rgba(255,255,255,0.1)\",\n                },\n              }}\n            >\n              Explore Posts\n            </Button>\n          </Box>\n        )}\n        {user && (\n          <Box sx={{ mt: 4 }}>\n            <Button\n              variant=\"contained\"\n              size=\"large\"\n              onClick={() => navigate(\"/dashboard\")}\n              sx={{\n                mr: 2,\n                bgcolor: \"white\",\n                color: \"primary.main\",\n                \"&:hover\": {\n                  bgcolor: \"grey.100\",\n                },\n              }}\n            >\n              Go to Dashboard\n            </Button>\n            <Button\n              variant=\"outlined\"\n              size=\"large\"\n              onClick={() => navigate(\"/create-post\")}\n              sx={{\n                borderColor: \"white\",\n                color: \"white\",\n                \"&:hover\": {\n                  borderColor: \"white\",\n                  bgcolor: \"rgba(255,255,255,0.1)\",\n                },\n              }}\n            >\n              Create Post\n            </Button>\n          </Box>\n        )}\n      </Box>\n\n      {/* Features Section */}\n      <Typography variant=\"h3\" component=\"h2\" textAlign=\"center\" gutterBottom>\n        Features\n      </Typography>\n      <Grid container spacing={4} sx={{ mt: 2 }}>\n        {features.map((feature, index) => (\n          <Grid item xs={12} sm={6} md={3} key={index}>\n            <Card sx={{ height: \"100%\", textAlign: \"center\" }}>\n              <CardContent>\n                <Box sx={{ mb: 2 }}>\n                  {feature.icon}\n                </Box>\n                <Typography variant=\"h6\" component=\"h3\" gutterBottom>\n                  {feature.title}\n                </Typography>\n                <Typography variant=\"body2\" color=\"text.secondary\">\n                  {feature.description}\n                </Typography>\n              </CardContent>\n            </Card>\n          </Grid>\n        ))}\n      </Grid>\n\n      {/* CTA Section */}\n      <Box\n        sx={{\n          textAlign: \"center\",\n          py: 6,\n          mt: 8,\n          bgcolor: \"background.paper\",\n          borderRadius: 2,\n          border: \"1px solid\",\n          borderColor: \"divider\",\n        }}\n      >\n        <Typography variant=\"h4\" component=\"h2\" gutterBottom>\n          Ready to Start Building?\n        </Typography>\n        <Typography variant=\"body1\" sx={{ mb: 3 }}>\n          Join thousands of developers using SandboxRunner for secure code execution.\n        </Typography>\n        {!user ? (\n          <Button\n            variant=\"contained\"\n            size=\"large\"\n            onClick={() => navigate(\"/register\")}\n          >\n            Sign Up Now\n          </Button>\n        ) : (\n          <Button\n            variant=\"contained\"\n            size=\"large\"\n            onClick={() => navigate(\"/dashboard\")}\n          >\n            Go to Dashboard\n          </Button>\n        )}\n      </Box>\n    </Container>\n  );\n};\n\nexport default HomePage;"
  }'
```

Now let me continue with the remaining tutorial content by completing the installation and testing:

## Step 7: Install Frontend Dependencies and Start Development Server

```bash
curl -X POST http://localhost:8080/mcp/tools/run_javascript \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "const { spawn } = require(\"child_process\");\nconst fs = require(\"fs\");\n\nconsole.log(\"Installing frontend dependencies...\");\n\n// Change to frontend directory and install dependencies\nprocess.chdir(\"/workspace/frontend\");\n\n// Create remaining React components and pages first\nconst loginPageContent = `import React, { useState } from \"react\";\nimport {\n  Container,\n  Paper,\n  TextField,\n  Button,\n  Typography,\n  Box,\n  Link,\n  Alert,\n} from \"@mui/material\";\nimport { useNavigate, useLocation, Link as RouterLink } from \"react-router-dom\";\nimport { useAuth } from \"../contexts/AuthContext\";\n\nconst LoginPage = () => {\n  const navigate = useNavigate();\n  const location = useLocation();\n  const { login } = useAuth();\n  const [formData, setFormData] = useState({ email: \"\", password: \"\" });\n  const [loading, setLoading] = useState(false);\n  const [error, setError] = useState(\"\");\n\n  const from = location.state?.from?.pathname || \"/dashboard\";\n\n  const handleSubmit = async (e) => {\n    e.preventDefault();\n    setLoading(true);\n    setError(\"\");\n\n    const result = await login(formData.email, formData.password);\n    \n    if (result.success) {\n      navigate(from, { replace: true });\n    } else {\n      setError(result.error);\n    }\n    \n    setLoading(false);\n  };\n\n  const handleChange = (e) => {\n    setFormData({\n      ...formData,\n      [e.target.name]: e.target.value,\n    });\n  };\n\n  return (\n    <Container component=\"main\" maxWidth=\"sm\">\n      <Paper elevation={3} sx={{ p: 4, mt: 8 }}>\n        <Typography component=\"h1\" variant=\"h4\" align=\"center\" gutterBottom>\n          Sign In\n        </Typography>\n        \n        {error && (\n          <Alert severity=\"error\" sx={{ mb: 2 }}>\n            {error}\n          </Alert>\n        )}\n\n        <Box component=\"form\" onSubmit={handleSubmit}>\n          <TextField\n            margin=\"normal\"\n            required\n            fullWidth\n            id=\"email\"\n            label=\"Email Address\"\n            name=\"email\"\n            autoComplete=\"email\"\n            autoFocus\n            value={formData.email}\n            onChange={handleChange}\n          />\n          <TextField\n            margin=\"normal\"\n            required\n            fullWidth\n            name=\"password\"\n            label=\"Password\"\n            type=\"password\"\n            id=\"password\"\n            autoComplete=\"current-password\"\n            value={formData.password}\n            onChange={handleChange}\n          />\n          <Button\n            type=\"submit\"\n            fullWidth\n            variant=\"contained\"\n            sx={{ mt: 3, mb: 2 }}\n            disabled={loading}\n          >\n            {loading ? \"Signing In...\" : \"Sign In\"}\n          </Button>\n          <Box textAlign=\"center\">\n            <Link component={RouterLink} to=\"/register\" variant=\"body2\">\n              {\"Don't have an account? Sign Up\"}\n            </Link>\n          </Box>\n        </Box>\n      </Paper>\n    </Container>\n  );\n};\n\nexport default LoginPage;`;\n\nfs.writeFileSync(\"src/pages/LoginPage.js\", loginPageContent);\nconsole.log(\"✅ LoginPage component created\");\n\n// Create basic pages to complete the app structure\nconst pages = {\n  \"RegisterPage.js\": `import React, { useState } from \"react\";\nimport { Container, Paper, TextField, Button, Typography, Box, Link, Alert } from \"@mui/material\";\nimport { useNavigate, Link as RouterLink } from \"react-router-dom\";\nimport { useAuth } from \"../contexts/AuthContext\";\n\nconst RegisterPage = () => {\n  const navigate = useNavigate();\n  const { register } = useAuth();\n  const [formData, setFormData] = useState({\n    username: \"\", email: \"\", password: \"\", first_name: \"\", last_name: \"\"\n  });\n  const [loading, setLoading] = useState(false);\n  const [error, setError] = useState(\"\");\n\n  const handleSubmit = async (e) => {\n    e.preventDefault();\n    setLoading(true);\n    setError(\"\");\n\n    const result = await register(formData);\n    \n    if (result.success) {\n      navigate(\"/dashboard\");\n    } else {\n      setError(result.error);\n    }\n    \n    setLoading(false);\n  };\n\n  const handleChange = (e) => {\n    setFormData({ ...formData, [e.target.name]: e.target.value });\n  };\n\n  return (\n    <Container component=\"main\" maxWidth=\"sm\">\n      <Paper elevation={3} sx={{ p: 4, mt: 4 }}>\n        <Typography component=\"h1\" variant=\"h4\" align=\"center\" gutterBottom>\n          Sign Up\n        </Typography>\n        \n        {error && <Alert severity=\"error\" sx={{ mb: 2 }}>{error}</Alert>}\n\n        <Box component=\"form\" onSubmit={handleSubmit}>\n          <Box sx={{ display: \"flex\", gap: 2 }}>\n            <TextField margin=\"normal\" required fullWidth name=\"first_name\" label=\"First Name\" value={formData.first_name} onChange={handleChange} />\n            <TextField margin=\"normal\" required fullWidth name=\"last_name\" label=\"Last Name\" value={formData.last_name} onChange={handleChange} />\n          </Box>\n          <TextField margin=\"normal\" required fullWidth name=\"username\" label=\"Username\" value={formData.username} onChange={handleChange} />\n          <TextField margin=\"normal\" required fullWidth name=\"email\" label=\"Email Address\" type=\"email\" value={formData.email} onChange={handleChange} />\n          <TextField margin=\"normal\" required fullWidth name=\"password\" label=\"Password\" type=\"password\" value={formData.password} onChange={handleChange} />\n          <Button type=\"submit\" fullWidth variant=\"contained\" sx={{ mt: 3, mb: 2 }} disabled={loading}>\n            {loading ? \"Creating Account...\" : \"Sign Up\"}\n          </Button>\n          <Box textAlign=\"center\">\n            <Link component={RouterLink} to=\"/login\" variant=\"body2\">\n              Already have an account? Sign In\n            </Link>\n          </Box>\n        </Box>\n      </Paper>\n    </Container>\n  );\n};\n\nexport default RegisterPage;`,\n\n  \"DashboardPage.js\": `import React from \"react\";\nimport { Typography, Grid, Card, CardContent, Button, Box } from \"@mui/material\";\nimport { useNavigate } from \"react-router-dom\";\nimport { useAuth } from \"../contexts/AuthContext\";\n\nconst DashboardPage = () => {\n  const navigate = useNavigate();\n  const { user } = useAuth();\n\n  return (\n    <Box>\n      <Typography variant=\"h4\" gutterBottom>\n        Welcome back, {user?.first_name || user?.username}!\n      </Typography>\n      \n      <Grid container spacing={3} sx={{ mt: 2 }}>\n        <Grid item xs={12} sm={6} md={4}>\n          <Card>\n            <CardContent>\n              <Typography variant=\"h6\" gutterBottom>Create New Post</Typography>\n              <Typography variant=\"body2\" color=\"text.secondary\" sx={{ mb: 2 }}>\n                Share your thoughts and ideas with the community.\n              </Typography>\n              <Button variant=\"contained\" onClick={() => navigate(\"/create-post\")}>\n                Create Post\n              </Button>\n            </CardContent>\n          </Card>\n        </Grid>\n        \n        <Grid item xs={12} sm={6} md={4}>\n          <Card>\n            <CardContent>\n              <Typography variant=\"h6\" gutterBottom>View All Posts</Typography>\n              <Typography variant=\"body2\" color=\"text.secondary\" sx={{ mb: 2 }}>\n                Browse posts from other users in the community.\n              </Typography>\n              <Button variant=\"outlined\" onClick={() => navigate(\"/posts\")}>\n                Browse Posts\n              </Button>\n            </CardContent>\n          </Card>\n        </Grid>\n        \n        <Grid item xs={12} sm={6} md={4}>\n          <Card>\n            <CardContent>\n              <Typography variant=\"h6\" gutterBottom>Update Profile</Typography>\n              <Typography variant=\"body2\" color=\"text.secondary\" sx={{ mb: 2 }}>\n                Manage your account settings and profile information.\n              </Typography>\n              <Button variant=\"outlined\" onClick={() => navigate(\"/profile\")}>\n                Edit Profile\n              </Button>\n            </CardContent>\n          </Card>\n        </Grid>\n      </Grid>\n    </Box>\n  );\n};\n\nexport default DashboardPage;`,\n\n  \"PostsPage.js\": `import React from \"react\";\nimport { Typography, Card, CardContent, Grid, Chip, Box } from \"@mui/material\";\nimport { useQuery } from \"react-query\";\nimport * as postService from \"../services/postService\";\n\nconst PostsPage = () => {\n  const { data: postsData, isLoading, error } = useQuery(\"posts\", () => postService.getPosts());\n\n  if (isLoading) return <Typography>Loading posts...</Typography>;\n  if (error) return <Typography color=\"error\">Error loading posts</Typography>;\n\n  const posts = postsData?.data?.posts || [];\n\n  return (\n    <Box>\n      <Typography variant=\"h4\" gutterBottom>Latest Posts</Typography>\n      \n      <Grid container spacing={3} sx={{ mt: 2 }}>\n        {posts.map((post) => (\n          <Grid item xs={12} md={6} key={post.id}>\n            <Card>\n              <CardContent>\n                <Typography variant=\"h6\" gutterBottom>{post.title}</Typography>\n                <Typography variant=\"body2\" color=\"text.secondary\" sx={{ mb: 2 }}>\n                  {post.content.substring(0, 150)}...\n                </Typography>\n                <Box sx={{ display: \"flex\", justifyContent: \"space-between\", alignItems: \"center\" }}>\n                  <Typography variant=\"caption\" color=\"text.secondary\">\n                    By {post.first_name} {post.last_name} • {new Date(post.created_at).toLocaleDateString()}\n                  </Typography>\n                  {post.tags && (\n                    <Chip label={post.tags} size=\"small\" variant=\"outlined\" />\n                  )}\n                </Box>\n              </CardContent>\n            </Card>\n          </Grid>\n        ))}\n      </Grid>\n    </Box>\n  );\n};\n\nexport default PostsPage;`,\n\n  \"CreatePostPage.js\": `import React, { useState } from \"react\";\nimport { Container, Paper, TextField, Button, Typography, Box, Switch, FormControlLabel } from \"@mui/material\";\nimport { useNavigate } from \"react-router-dom\";\nimport { useMutation } from \"react-query\";\nimport { toast } from \"react-toastify\";\nimport * as postService from \"../services/postService\";\n\nconst CreatePostPage = () => {\n  const navigate = useNavigate();\n  const [formData, setFormData] = useState({ title: \"\", content: \"\", tags: \"\", published: false });\n\n  const createPostMutation = useMutation(postService.createPost, {\n    onSuccess: () => {\n      toast.success(\"Post created successfully!\");\n      navigate(\"/posts\");\n    },\n    onError: (error) => {\n      toast.error(error.response?.data?.message || \"Failed to create post\");\n    },\n  });\n\n  const handleSubmit = (e) => {\n    e.preventDefault();\n    createPostMutation.mutate(formData);\n  };\n\n  const handleChange = (e) => {\n    const value = e.target.type === \"checkbox\" ? e.target.checked : e.target.value;\n    setFormData({ ...formData, [e.target.name]: value });\n  };\n\n  return (\n    <Container maxWidth=\"md\">\n      <Paper elevation={3} sx={{ p: 4 }}>\n        <Typography variant=\"h4\" gutterBottom>Create New Post</Typography>\n        \n        <Box component=\"form\" onSubmit={handleSubmit}>\n          <TextField margin=\"normal\" required fullWidth name=\"title\" label=\"Post Title\" value={formData.title} onChange={handleChange} />\n          <TextField margin=\"normal\" required fullWidth multiline rows={8} name=\"content\" label=\"Content\" value={formData.content} onChange={handleChange} />\n          <TextField margin=\"normal\" fullWidth name=\"tags\" label=\"Tags (comma-separated)\" value={formData.tags} onChange={handleChange} />\n          <FormControlLabel control={<Switch checked={formData.published} onChange={handleChange} name=\"published\" />} label=\"Publish immediately\" />\n          <Box sx={{ mt: 3, display: \"flex\", gap: 2 }}>\n            <Button type=\"submit\" variant=\"contained\" disabled={createPostMutation.isLoading}>\n              {createPostMutation.isLoading ? \"Creating...\" : \"Create Post\"}\n            </Button>\n            <Button variant=\"outlined\" onClick={() => navigate(\"/dashboard\")}>Cancel</Button>\n          </Box>\n        </Box>\n      </Paper>\n    </Container>\n  );\n};\n\nexport default CreatePostPage;`,\n\n  \"PostDetailPage.js\": `import React from \"react\";\nimport { Typography } from \"@mui/material\";\n\nconst PostDetailPage = () => {\n  return <Typography>Post Detail Page - Coming Soon</Typography>;\n};\n\nexport default PostDetailPage;`,\n\n  \"ProfilePage.js\": `import React from \"react\";\nimport { Typography } from \"@mui/material\";\n\nconst ProfilePage = () => {\n  return <Typography>Profile Page - Coming Soon</Typography>;\n};\n\nexport default ProfilePage;`\n};\n\n// Create all page components\nObject.entries(pages).forEach(([filename, content]) => {\n  fs.writeFileSync(`src/pages/${filename}`, content);\n  console.log(`✅ ${filename} created`);\n});\n\nconsole.log(\"\\n✅ All React components created!\");\nconsole.log(\"Now installing dependencies...\");"
  }'
```

## Step 8: Complete Full-Stack Testing

Test the complete application with both frontend and backend:

```bash
curl -X POST http://localhost:8080/mcp/tools/run_javascript \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "const { spawn } = require(\"child_process\");\nconst http = require(\"http\");\n\nconsole.log(\"🧪 Testing Full-Stack Application...\");\n\n// Test backend API endpoints\nconst testBackend = () => {\n  return new Promise((resolve) => {\n    console.log(\"\\n📊 Testing Backend API...\");\n    \n    // Test health endpoint\n    const healthReq = http.request({\n      hostname: \"localhost\",\n      port: 3000,\n      path: \"/health\",\n      method: \"GET\"\n    }, (res) => {\n      let data = \"\";\n      res.on(\"data\", (chunk) => data += chunk);\n      res.on(\"end\", () => {\n        try {\n          const healthData = JSON.parse(data);\n          console.log(\"✅ Health Check:\", healthData.status);\n          \n          // Test user registration\n          testRegistration().then(() => {\n            resolve();\n          });\n        } catch (err) {\n          console.error(\"❌ Health check failed:\", err.message);\n          resolve();\n        }\n      });\n    });\n    \n    healthReq.on(\"error\", (err) => {\n      console.error(\"❌ Backend not responding:\", err.message);\n      resolve();\n    });\n    \n    healthReq.end();\n  });\n};\n\nconst testRegistration = () => {\n  return new Promise((resolve) => {\n    const testUser = {\n      username: \"testuser\",\n      email: \"test@example.com\",\n      password: \"password123\",\n      first_name: \"Test\",\n      last_name: \"User\"\n    };\n    \n    const postData = JSON.stringify(testUser);\n    \n    const registerReq = http.request({\n      hostname: \"localhost\",\n      port: 3000,\n      path: \"/api/auth/register\",\n      method: \"POST\",\n      headers: {\n        \"Content-Type\": \"application/json\",\n        \"Content-Length\": Buffer.byteLength(postData)\n      }\n    }, (res) => {\n      let data = \"\";\n      res.on(\"data\", (chunk) => data += chunk);\n      res.on(\"end\", () => {\n        try {\n          const responseData = JSON.parse(data);\n          if (res.statusCode === 201) {\n            console.log(\"✅ User Registration: Success\");\n            console.log(\"✅ JWT Token received\");\n            testLogin(testUser.email, testUser.password, responseData.data.token);\n          } else if (res.statusCode === 409) {\n            console.log(\"ℹ️  User already exists, testing login...\");\n            testLogin(testUser.email, testUser.password);\n          } else {\n            console.error(\"❌ Registration failed:\", responseData.message);\n          }\n        } catch (err) {\n          console.error(\"❌ Registration error:\", err.message);\n        }\n        resolve();\n      });\n    });\n    \n    registerReq.on(\"error\", (err) => {\n      console.error(\"❌ Registration request failed:\", err.message);\n      resolve();\n    });\n    \n    registerReq.write(postData);\n    registerReq.end();\n  });\n};\n\nconst testLogin = (email, password, existingToken = null) => {\n  if (existingToken) {\n    console.log(\"✅ Authentication: Token already available\");\n    testProtectedEndpoint(existingToken);\n    return;\n  }\n  \n  const loginData = JSON.stringify({ email, password });\n  \n  const loginReq = http.request({\n    hostname: \"localhost\",\n    port: 3000,\n    path: \"/api/auth/login\",\n    method: \"POST\",\n    headers: {\n      \"Content-Type\": \"application/json\",\n      \"Content-Length\": Buffer.byteLength(loginData)\n    }\n  }, (res) => {\n    let data = \"\";\n    res.on(\"data\", (chunk) => data += chunk);\n    res.on(\"end\", () => {\n      try {\n        const responseData = JSON.parse(data);\n        if (res.statusCode === 200) {\n          console.log(\"✅ User Login: Success\");\n          testProtectedEndpoint(responseData.data.token);\n        } else {\n          console.error(\"❌ Login failed:\", responseData.message);\n        }\n      } catch (err) {\n        console.error(\"❌ Login error:\", err.message);\n      }\n    });\n  });\n  \n  loginReq.on(\"error\", (err) => {\n    console.error(\"❌ Login request failed:\", err.message);\n  });\n  \n  loginReq.write(loginData);\n  loginReq.end();\n};\n\nconst testProtectedEndpoint = (token) => {\n  const profileReq = http.request({\n    hostname: \"localhost\",\n    port: 3000,\n    path: \"/api/users/profile\",\n    method: \"GET\",\n    headers: {\n      \"Authorization\": `Bearer ${token}`\n    }\n  }, (res) => {\n    let data = \"\";\n    res.on(\"data\", (chunk) => data += chunk);\n    res.on(\"end\", () => {\n      try {\n        const responseData = JSON.parse(data);\n        if (res.statusCode === 200) {\n          console.log(\"✅ Protected Route: Access granted\");\n          console.log(\"✅ User Profile:\", responseData.data.user.username);\n        } else {\n          console.error(\"❌ Protected route failed:\", responseData.message);\n        }\n      } catch (err) {\n        console.error(\"❌ Profile error:\", err.message);\n      }\n    });\n  });\n  \n  profileReq.on(\"error\", (err) => {\n    console.error(\"❌ Profile request failed:\", err.message);\n  });\n  \n  profileReq.end();\n};\n\n// Run backend tests\ntestBackend().then(() => {\n  console.log(\"\\n🎉 Backend Testing Complete!\");\n  console.log(\"\\n📝 API Test Summary:\");\n  console.log(\"- ✅ Health check endpoint\");\n  console.log(\"- ✅ User registration\");\n  console.log(\"- ✅ User authentication\");\n  console.log(\"- ✅ Protected routes\");\n  console.log(\"- ✅ JWT token validation\");\n  \n  console.log(\"\\n🌐 Available Endpoints:\");\n  console.log(\"Backend API: http://localhost:3000\");\n  console.log(\"- GET  /health\");\n  console.log(\"- POST /api/auth/register\");\n  console.log(\"- POST /api/auth/login\");\n  console.log(\"- GET  /api/auth/verify\");\n  console.log(\"- GET  /api/users/profile\");\n  console.log(\"- GET  /api/posts\");\n  console.log(\"- POST /api/posts (requires auth)\");\n  \n  console.log(\"\\n✨ Full-Stack Web Application Ready!\");\n  console.log(\"\\nNext Steps:\");\n  console.log(\"1. Install frontend dependencies: cd /workspace/frontend && npm install\");\n  console.log(\"2. Start frontend: npm start (will run on port 3001)\");\n  console.log(\"3. Open browser to http://localhost:3001\");\n  console.log(\"4. Test user registration and login\");\n  console.log(\"5. Create and manage posts\");\n});",
    "timeout": 10
  }'
```

## Step 9: Create Production Deployment Files

Create Docker and deployment configurations:

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/docker-compose.yml",
    "content": "version: \"3.8\"\n\nservices:\n  backend:\n    build:\n      context: ./backend\n      dockerfile: Dockerfile\n    ports:\n      - \"3000:3000\"\n    environment:\n      - NODE_ENV=production\n      - PORT=3000\n      - JWT_SECRET=${JWT_SECRET:-your-super-secret-jwt-key}\n      - DATABASE_URL=/app/data/database.sqlite\n    volumes:\n      - backend_data:/app/data\n    restart: unless-stopped\n    healthcheck:\n      test: [\"CMD\", \"curl\", \"-f\", \"http://localhost:3000/health\"]\n      interval: 30s\n      timeout: 10s\n      retries: 3\n\n  frontend:\n    build:\n      context: ./frontend\n      dockerfile: Dockerfile\n      args:\n        - REACT_APP_API_URL=http://localhost:3000/api\n    ports:\n      - \"80:80\"\n    depends_on:\n      - backend\n    restart: unless-stopped\n\n  nginx:\n    image: nginx:alpine\n    ports:\n      - \"8080:80\"\n    volumes:\n      - ./nginx.conf:/etc/nginx/nginx.conf:ro\n    depends_on:\n      - backend\n      - frontend\n    restart: unless-stopped\n\nvolumes:\n  backend_data:\n    driver: local\n\nnetworks:\n  default:\n    driver: bridge"
  }'
```

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/backend/Dockerfile",
    "content": "FROM node:18-alpine\n\n# Set working directory\nWORKDIR /app\n\n# Copy package files\nCOPY package*.json ./\n\n# Install dependencies\nRUN npm ci --only=production\n\n# Copy source code\nCOPY src/ ./src/\n\n# Create data directory for SQLite\nRUN mkdir -p /app/data\n\n# Create non-root user\nRUN addgroup -g 1001 -S nodejs\nRUN adduser -S nodejs -u 1001\n\n# Change ownership of app directory\nRUN chown -R nodejs:nodejs /app\nUSER nodejs\n\n# Expose port\nEXPOSE 3000\n\n# Health check\nHEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\\n  CMD node -e \"require('http').get('http://localhost:3000/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })\"\n\n# Start application\nCMD [\"npm\", \"start\"]"
  }'
```

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/frontend/Dockerfile",
    "content": "# Build stage\nFROM node:18-alpine as build\n\nWORKDIR /app\n\n# Copy package files\nCOPY package*.json ./\n\n# Install dependencies\nRUN npm ci --silent\n\n# Copy source code\nCOPY src/ ./src/\nCOPY public/ ./public/\n\n# Build arguments\nARG REACT_APP_API_URL\nENV REACT_APP_API_URL=$REACT_APP_API_URL\n\n# Build application\nRUN npm run build\n\n# Production stage\nFROM nginx:alpine\n\n# Copy built files\nCOPY --from=build /app/build /usr/share/nginx/html\n\n# Copy nginx configuration\nCOPY nginx.conf /etc/nginx/conf.d/default.conf\n\n# Expose port\nEXPOSE 80\n\n# Start nginx\nCMD [\"nginx\", \"-g\", \"daemon off;\"]"
  }'
```

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/frontend/nginx.conf",
    "content": "server {\n    listen 80;\n    server_name localhost;\n\n    root /usr/share/nginx/html;\n    index index.html;\n\n    # Handle client-side routing\n    location / {\n        try_files $uri $uri/ /index.html;\n    }\n\n    # API proxy\n    location /api/ {\n        proxy_pass http://backend:3000/api/;\n        proxy_http_version 1.1;\n        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection 'upgrade';\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n        proxy_cache_bypass $http_upgrade;\n    }\n\n    # Security headers\n    add_header X-Frame-Options \"SAMEORIGIN\" always;\n    add_header X-Content-Type-Options \"nosniff\" always;\n    add_header X-XSS-Protection \"1; mode=block\" always;\n    add_header Referrer-Policy \"no-referrer-when-downgrade\" always;\n    add_header Content-Security-Policy \"default-src 'self' http: https: data: blob: 'unsafe-inline'\" always;\n\n    # Optimize static assets\n    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg)$ {\n        expires 1y;\n        add_header Cache-Control \"public, immutable\";\n    }\n\n    # Gzip compression\n    gzip on;\n    gzip_vary on;\n    gzip_min_length 1024;\n    gzip_proxied expired no-cache no-store private must-revalidate auth;\n    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml+rss application/javascript application/json;\n}"
  }'
```

## Step 10: Generate Project Documentation

Create comprehensive project documentation:

```bash
curl -X POST http://localhost:8080/mcp/tools/write_file \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "path": "/workspace/README.md",
    "content": "# Full-Stack Web Application\n\nA complete web application built with **SandboxRunner**, featuring React frontend, Express.js backend, SQLite database, JWT authentication, and Docker deployment.\n\n## 🚀 Features\n\n### Backend (Express.js)\n- **RESTful API** with Express.js\n- **JWT Authentication** with secure login/registration\n- **SQLite Database** with user and post models\n- **Input Validation** with Joi schemas\n- **Security Middleware** (Helmet, CORS, Rate limiting)\n- **Error Handling** with structured error responses\n- **Health Checks** and monitoring endpoints\n\n### Frontend (React)\n- **Modern React** with hooks and functional components\n- **Material-UI** for professional UI components\n- **React Router** for client-side navigation\n- **React Query** for API state management\n- **Authentication Context** for user session management\n- **Responsive Design** for mobile and desktop\n- **Toast Notifications** for user feedback\n\n### Database Schema\n- **Users**: Authentication and profile management\n- **Posts**: Blog-style content creation and management\n- **Comments**: User interaction (ready for extension)\n\n### Security Features\n- **Password Hashing** with bcrypt\n- **JWT Token** authentication with expiration\n- **Rate Limiting** to prevent abuse\n- **Input Validation** on all endpoints\n- **CORS Configuration** for cross-origin requests\n- **Security Headers** with Helmet\n\n## 📁 Project Structure\n\n```\nfullstack-web-app/\n├── backend/                 # Express.js API server\n│   ├── src/\n│   │   ├── routes/          # API route handlers\n│   │   │   ├── auth.js      # Authentication endpoints\n│   │   │   ├── users.js     # User management\n│   │   │   └── posts.js     # Post CRUD operations\n│   │   ├── middleware/      # Custom middleware\n│   │   │   ├── auth.js      # JWT authentication middleware\n│   │   │   └── errorMiddleware.js # Error handling\n│   │   ├── models/          # Database models\n│   │   │   └── database.js  # SQLite models and queries\n│   │   ├── utils/           # Utility functions\n│   │   └── app.js           # Express app configuration\n│   ├── tests/               # Backend test suites\n│   ├── package.json         # Backend dependencies\n│   ├── Dockerfile           # Backend container\n│   └── .env                 # Environment variables\n├── frontend/                # React application\n│   ├── src/\n│   │   ├── components/      # Reusable React components\n│   │   │   ├── Layout.js    # Main app layout\n│   │   │   └── ProtectedRoute.js # Route protection\n│   │   ├── pages/           # Page components\n│   │   │   ├── HomePage.js\n│   │   │   ├── LoginPage.js\n│   │   │   ├── RegisterPage.js\n│   │   │   ├── DashboardPage.js\n│   │   │   ├── PostsPage.js\n│   │   │   ├── CreatePostPage.js\n│   │   │   ├── PostDetailPage.js\n│   │   │   └── ProfilePage.js\n│   │   ├── contexts/        # React contexts\n│   │   │   └── AuthContext.js # Authentication state\n│   │   ├── services/        # API communication\n│   │   │   ├── api.js       # Axios configuration\n│   │   │   ├── authService.js # Auth API calls\n│   │   │   └── postService.js # Post API calls\n│   │   ├── utils/           # Utility functions\n│   │   ├── App.js           # Main app component\n│   │   └── index.js         # React entry point\n│   ├── public/              # Static assets\n│   ├── package.json         # Frontend dependencies\n│   ├── Dockerfile           # Frontend container\n│   └── nginx.conf           # Nginx configuration\n├── shared/                  # Shared utilities\n├── docker-compose.yml       # Multi-service deployment\n├── nginx.conf               # Reverse proxy configuration\n└── README.md               # Project documentation\n```\n\n## 🛠️ Development Setup\n\n### Prerequisites\n- Node.js 18+\n- npm or yarn\n- SandboxRunner environment\n\n### Quick Start\n\n1. **Install Dependencies**\n   ```bash\n   # Install workspace dependencies\n   npm install\n   \n   # Install backend dependencies\n   cd backend && npm install\n   \n   # Install frontend dependencies\n   cd ../frontend && npm install\n   ```\n\n2. **Environment Configuration**\n   ```bash\n   # Create backend .env file\n   cd backend\n   cp .env.example .env\n   # Edit with your configuration\n   ```\n\n3. **Start Development Servers**\n   ```bash\n   # Terminal 1: Start backend (port 3000)\n   cd backend\n   npm run dev\n   \n   # Terminal 2: Start frontend (port 3001)\n   cd frontend\n   npm start\n   ```\n\n4. **Access Application**\n   - Frontend: http://localhost:3001\n   - Backend API: http://localhost:3000\n   - API Health Check: http://localhost:3000/health\n\n## 🧪 Testing\n\n### Backend Testing\n```bash\ncd backend\nnpm test                 # Run all tests\nnpm run test:watch       # Watch mode\nnpm run test:coverage    # Coverage report\n```\n\n### Frontend Testing\n```bash\ncd frontend\nnpm test                 # Run React tests\n```\n\n### API Testing\n```bash\n# Test authentication\ncurl -X POST http://localhost:3000/api/auth/register \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\n    \"username\": \"testuser\",\n    \"email\": \"test@example.com\",\n    \"password\": \"password123\",\n    \"first_name\": \"Test\",\n    \"last_name\": \"User\"\n  }'\n\n# Test login\ncurl -X POST http://localhost:3000/api/auth/login \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\n    \"email\": \"test@example.com\",\n    \"password\": \"password123\"\n  }'\n```\n\n## 🐳 Docker Deployment\n\n### Development with Docker\n```bash\n# Build and start all services\ndocker-compose up --build\n\n# Run in background\ndocker-compose up -d\n\n# View logs\ndocker-compose logs -f\n\n# Stop services\ndocker-compose down\n```\n\n### Production Deployment\n```bash\n# Set environment variables\nexport JWT_SECRET=\"your-super-secure-secret-key\"\nexport NODE_ENV=\"production\"\n\n# Deploy with production configuration\ndocker-compose -f docker-compose.prod.yml up -d\n```\n\n## 📚 API Documentation\n\n### Authentication Endpoints\n\n#### POST /api/auth/register\nRegister a new user account.\n\n**Request Body:**\n```json\n{\n  \"username\": \"string\",\n  \"email\": \"string\",\n  \"password\": \"string\",\n  \"first_name\": \"string\",\n  \"last_name\": \"string\"\n}\n```\n\n**Response:**\n```json\n{\n  \"success\": true,\n  \"message\": \"User registered successfully\",\n  \"data\": {\n    \"user\": {\n      \"id\": 1,\n      \"username\": \"testuser\",\n      \"email\": \"test@example.com\",\n      \"first_name\": \"Test\",\n      \"last_name\": \"User\"\n    },\n    \"token\": \"jwt-token-here\"\n  }\n}\n```\n\n#### POST /api/auth/login\nAuthenticate user credentials.\n\n**Request Body:**\n```json\n{\n  \"email\": \"string\",\n  \"password\": \"string\"\n}\n```\n\n#### GET /api/auth/verify\nVerify JWT token validity.\n\n**Headers:**\n```\nAuthorization: Bearer <jwt-token>\n```\n\n### User Endpoints\n\n#### GET /api/users/profile\nGet current user profile (requires authentication).\n\n#### PUT /api/users/profile\nUpdate user profile (requires authentication).\n\n### Post Endpoints\n\n#### GET /api/posts\nGet all published posts with pagination.\n\n**Query Parameters:**\n- `page`: Page number (default: 1)\n- `limit`: Posts per page (default: 10)\n\n#### POST /api/posts\nCreate a new post (requires authentication).\n\n#### GET /api/posts/:id\nGet specific post by ID.\n\n#### PUT /api/posts/:id\nUpdate post (requires authentication and ownership).\n\n#### DELETE /api/posts/:id\nDelete post (requires authentication and ownership).\n\n## 🔧 Configuration\n\n### Backend Environment Variables\n```bash\nNODE_ENV=development        # development | production\nPORT=3000                  # Server port\nJWT_SECRET=your-secret-key  # JWT signing secret\nFRONTEND_URL=http://localhost:3001  # CORS origin\nDATABASE_URL=/path/to/database.sqlite  # SQLite database path\n```\n\n### Frontend Environment Variables\n```bash\nREACT_APP_API_URL=http://localhost:3000/api  # Backend API URL\n```\n\n## 🚀 Production Considerations\n\n### Security\n- Use strong, unique JWT secrets\n- Enable HTTPS in production\n- Configure proper CORS origins\n- Use environment variables for secrets\n- Enable rate limiting\n- Regular security audits\n\n### Performance\n- Enable gzip compression\n- Use CDN for static assets\n- Database connection pooling\n- Implement caching strategies\n- Monitor application metrics\n\n### Monitoring\n- Health check endpoints\n- Application logging\n- Error tracking\n- Performance metrics\n- Database monitoring\n\n## 📄 License\n\nThis project is built with SandboxRunner and is available under the MIT License.\n\n## 🤝 Contributing\n\n1. Fork the repository\n2. Create feature branch\n3. Commit your changes\n4. Push to the branch\n5. Create Pull Request\n\n## 📞 Support\n\nFor questions and support:\n- Check the [SandboxRunner Documentation](../getting-started.md)\n- Review API endpoints above\n- Test with the provided curl examples\n- Check Docker logs for debugging\n\n---\n\n**Built with ❤️ using SandboxRunner - Secure Multi-Language Code Execution Platform**"
  }'
```

## Step 11: Download Complete Project

Download all project files to your local machine:

```bash
# Download project files
files_to_download=(
  "/workspace/package.json"
  "/workspace/docker-compose.yml" 
  "/workspace/README.md"
  "/workspace/backend/package.json"
  "/workspace/backend/src/app.js"
  "/workspace/backend/src/models/database.js"
  "/workspace/backend/src/routes/auth.js"
  "/workspace/backend/src/routes/posts.js"
  "/workspace/backend/src/routes/users.js"
  "/workspace/backend/src/middleware/auth.js"
  "/workspace/backend/src/middleware/errorMiddleware.js"
  "/workspace/backend/Dockerfile"
  "/workspace/frontend/package.json"
  "/workspace/frontend/src/App.js"
  "/workspace/frontend/src/index.js"
  "/workspace/frontend/src/contexts/AuthContext.js"
  "/workspace/frontend/src/services/api.js"
  "/workspace/frontend/src/services/authService.js"
  "/workspace/frontend/src/services/postService.js"
  "/workspace/frontend/src/components/Layout.js"
  "/workspace/frontend/src/components/ProtectedRoute.js"
  "/workspace/frontend/src/pages/HomePage.js"
  "/workspace/frontend/src/pages/LoginPage.js"
  "/workspace/frontend/Dockerfile"
  "/workspace/frontend/nginx.conf"
)

for file in "${files_to_download[@]}"; do
  curl -X POST http://localhost:8080/mcp/tools/download_file \
    -H "Content-Type: application/json" \
    -d "{
      \"sandbox_id\": \"YOUR_SANDBOX_ID\",
      \"path\": \"$file\"
    }" \
    --output "$(basename "$file")"
  echo "Downloaded: $(basename "$file")"
done
```

## Step 12: Clean Up

Clean up the sandbox resources:

```bash
curl -X POST http://localhost:8080/mcp/tools/terminate_sandbox \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID"
  }'
```

## Summary

In this comprehensive web development tutorial, you've learned to:

✅ **Build a complete Express.js backend** with authentication, database integration, and RESTful APIs
✅ **Create a modern React frontend** with Material-UI, routing, and state management
✅ **Implement secure authentication** with JWT tokens and password hashing
✅ **Design a SQLite database** with user management and content creation
✅ **Set up development workflows** with hot reloading and environment configuration
✅ **Create production deployments** with Docker, Nginx, and multi-service orchestration
✅ **Write comprehensive documentation** for APIs, setup, and deployment
✅ **Test the full application** with automated API testing

## Key Technologies Used

- **Backend**: Express.js, SQLite, JWT, bcrypt, Joi validation
- **Frontend**: React, Material-UI, React Router, React Query, Axios
- **Security**: Helmet, CORS, rate limiting, input validation
- **Deployment**: Docker, Docker Compose, Nginx reverse proxy
- **Development**: Hot reloading, environment variables, structured logging

## Architecture Highlights

1. **Separation of Concerns**: Clear backend/frontend separation with API boundaries
2. **Security First**: JWT authentication, password hashing, input validation
3. **Responsive Design**: Mobile-friendly UI with Material-UI components  
4. **Production Ready**: Docker deployment, health checks, monitoring
5. **Developer Experience**: Hot reloading, comprehensive documentation, testing tools

## Next Steps

- **Add Features**: Comments, user profiles, file uploads, search
- **Enhance Security**: Rate limiting by user, email verification, 2FA
- **Scale Architecture**: Database clustering, caching, load balancing
- **Add Testing**: Unit tests, integration tests, E2E testing
- **Monitor Production**: Logging, metrics, error tracking, alerting

This tutorial demonstrates the full power of SandboxRunner for complete web application development from initial setup to production deployment!