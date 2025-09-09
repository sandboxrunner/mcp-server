package languages

import "regexp"

// getDefaultSecurityRules returns default security scanning rules
func getDefaultSecurityRules() []SecurityRule {
	return []SecurityRule{
		// Command Injection
		{
			ID:          "CMD_INJECTION_001",
			Name:        "Command Injection - os.system",
			Description: "Potential command injection vulnerability using os.system",
			Pattern:     regexp.MustCompile(`os\.system\s*\(`),
			Languages:   []Language{LanguagePython},
			Severity:    "high",
			Category:    "injection",
			Suggestion:  "Use subprocess module with proper argument sanitization",
		},
		{
			ID:          "CMD_INJECTION_002",
			Name:        "Command Injection - exec",
			Description: "Potential command injection vulnerability using exec functions",
			Pattern:     regexp.MustCompile(`(?:exec|system|popen)\s*\(`),
			Languages:   []Language{LanguageC, LanguageCPP},
			Severity:    "high",
			Category:    "injection",
			Suggestion:  "Use safer alternatives or validate input thoroughly",
		},
		{
			ID:          "CMD_INJECTION_003",
			Name:        "Command Injection - child_process",
			Description: "Potential command injection vulnerability using child_process",
			Pattern:     regexp.MustCompile(`child_process\.(?:exec|spawn)\s*\(`),
			Languages:   []Language{LanguageJavaScript, LanguageTypeScript},
			Severity:    "high",
			Category:    "injection",
			Suggestion:  "Use spawn with array arguments instead of exec with string",
		},

		// SQL Injection
		{
			ID:          "SQL_INJECTION_001",
			Name:        "SQL Injection - String Concatenation",
			Description: "Potential SQL injection using string concatenation",
			Pattern:     regexp.MustCompile(`(?:SELECT|INSERT|UPDATE|DELETE).*\+.*['"]`),
			Languages:   []Language{LanguagePython, LanguageJavaScript, LanguageJava, LanguageCSharp},
			Severity:    "critical",
			Category:    "injection",
			Suggestion:  "Use parameterized queries or prepared statements",
		},

		// Path Traversal
		{
			ID:          "PATH_TRAVERSAL_001",
			Name:        "Path Traversal - Directory Traversal",
			Description: "Potential path traversal vulnerability",
			Pattern:     regexp.MustCompile(`\.\.\/|\.\.\\`),
			Languages:   []Language{LanguagePython, LanguageJavaScript, LanguageJava, LanguageGo, LanguageCSharp},
			Severity:    "medium",
			Category:    "path_traversal",
			Suggestion:  "Validate and sanitize file paths",
		},

		// Hardcoded Secrets
		{
			ID:          "HARDCODED_SECRET_001",
			Name:        "Hardcoded Password",
			Description: "Potential hardcoded password found",
			Pattern:     regexp.MustCompile(`(?i)password\s*=\s*['"][^'"]{3,}['"]`),
			Languages:   []Language{LanguagePython, LanguageJavaScript, LanguageJava, LanguageGo, LanguageCSharp},
			Severity:    "high",
			Category:    "secrets",
			Suggestion:  "Use environment variables or secure configuration management",
		},
		{
			ID:          "HARDCODED_SECRET_002",
			Name:        "Hardcoded API Key",
			Description: "Potential hardcoded API key found",
			Pattern:     regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|access[_-]?token)\s*=\s*['"][^'"]{10,}['"]`),
			Languages:   []Language{LanguagePython, LanguageJavaScript, LanguageJava, LanguageGo, LanguageCSharp},
			Severity:    "critical",
			Category:    "secrets",
			Suggestion:  "Use environment variables or secure vault systems",
		},

		// Cryptographic Issues
		{
			ID:          "CRYPTO_001",
			Name:        "Weak Cryptographic Hash",
			Description: "Use of weak cryptographic hash function",
			Pattern:     regexp.MustCompile(`(?:md5|sha1)\(`),
			Languages:   []Language{LanguagePython, LanguageJavaScript, LanguageJava, LanguageCSharp},
			Severity:    "medium",
			Category:    "cryptography",
			Suggestion:  "Use SHA-256 or stronger hash functions",
		},

		// Memory Safety (C/C++)
		{
			ID:          "MEMORY_SAFETY_001",
			Name:        "Buffer Overflow Risk - strcpy",
			Description: "Use of unsafe strcpy function",
			Pattern:     regexp.MustCompile(`strcpy\s*\(`),
			Languages:   []Language{LanguageC, LanguageCPP},
			Severity:    "high",
			Category:    "memory_safety",
			Suggestion:  "Use strncpy or safer alternatives",
		},
		{
			ID:          "MEMORY_SAFETY_002",
			Name:        "Buffer Overflow Risk - gets",
			Description: "Use of unsafe gets function",
			Pattern:     regexp.MustCompile(`gets\s*\(`),
			Languages:   []Language{LanguageC, LanguageCPP},
			Severity:    "critical",
			Category:    "memory_safety",
			Suggestion:  "Use fgets instead",
		},

		// Network Security
		{
			ID:          "NETWORK_001",
			Name:        "Unencrypted HTTP Connection",
			Description: "Use of unencrypted HTTP connection",
			Pattern:     regexp.MustCompile(`http://(?!localhost|127\.0\.0\.1)`),
			Languages:   []Language{LanguagePython, LanguageJavaScript, LanguageJava, LanguageGo, LanguageCSharp},
			Severity:    "medium",
			Category:    "network",
			Suggestion:  "Use HTTPS for external connections",
		},

		// File Operations
		{
			ID:          "FILE_OPERATIONS_001",
			Name:        "Unsafe File Permissions",
			Description: "Setting overly permissive file permissions",
			Pattern:     regexp.MustCompile(`(?:chmod|os\.chmod).*(?:777|666)`),
			Languages:   []Language{LanguagePython, LanguageShell},
			Severity:    "medium",
			Category:    "file_permissions",
			Suggestion:  "Use more restrictive file permissions",
		},

		// Deserialization
		{
			ID:          "DESERIALIZATION_001",
			Name:        "Unsafe Deserialization - pickle",
			Description: "Use of unsafe pickle deserialization",
			Pattern:     regexp.MustCompile(`pickle\.loads?\s*\(`),
			Languages:   []Language{LanguagePython},
			Severity:    "critical",
			Category:    "deserialization",
			Suggestion:  "Use safe serialization formats like JSON",
		},

		// Code Evaluation
		{
			ID:          "CODE_EVAL_001",
			Name:        "Code Evaluation - eval",
			Description: "Use of dangerous eval function",
			Pattern:     regexp.MustCompile(`eval\s*\(`),
			Languages:   []Language{LanguagePython, LanguageJavaScript},
			Severity:    "critical",
			Category:    "code_evaluation",
			Suggestion:  "Avoid eval or use safer alternatives",
		},

		// Information Disclosure
		{
			ID:          "INFO_DISCLOSURE_001",
			Name:        "Debug Information Exposure",
			Description: "Debug information may be exposed in production",
			Pattern:     regexp.MustCompile(`(?:DEBUG\s*=\s*True|console\.log|print\()`),
			Languages:   []Language{LanguagePython, LanguageJavaScript},
			Severity:    "low",
			Category:    "information_disclosure",
			Suggestion:  "Remove debug statements in production code",
		},
	}
}

// getBuiltInModules returns built-in modules for each language
func getBuiltInModules() map[Language][]string {
	return map[Language][]string{
		LanguagePython: {
			"os", "sys", "json", "re", "time", "datetime", "math", "random",
			"collections", "itertools", "functools", "operator", "typing",
			"pathlib", "urllib", "http", "socket", "threading", "multiprocessing",
			"subprocess", "tempfile", "shutil", "glob", "csv", "xml", "html",
			"base64", "hashlib", "hmac", "secrets", "ssl", "email", "logging",
			"unittest", "doctest", "argparse", "configparser", "io", "struct",
			"pickle", "copy", "weakref", "gc", "inspect", "dis", "trace",
		},
		LanguageJavaScript: {
			"fs", "path", "os", "crypto", "http", "https", "url", "querystring",
			"stream", "buffer", "events", "util", "assert", "child_process",
			"cluster", "dgram", "dns", "net", "readline", "repl", "tls",
			"vm", "zlib", "worker_threads", "async_hooks", "perf_hooks",
			"inspector", "trace_events", "v8", "process",
		},
		LanguageGo: {
			"fmt", "os", "io", "bufio", "strings", "strconv", "time", "math",
			"rand", "sort", "sync", "context", "errors", "flag", "log",
			"net", "http", "url", "json", "xml", "csv", "html", "regexp",
			"path", "filepath", "archive", "compress", "crypto", "encoding",
			"hash", "image", "database", "sql", "testing", "runtime",
		},
		LanguageRust: {
			"std", "core", "alloc", "proc_macro", "test", "collections",
			"fmt", "io", "net", "sync", "thread", "time", "env", "fs",
			"path", "process", "mem", "ptr", "slice", "str", "char",
			"f32", "f64", "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64",
		},
		LanguageJava: {
			"java.lang", "java.util", "java.io", "java.net", "java.text",
			"java.time", "java.math", "java.security", "java.nio", "java.sql",
			"java.awt", "java.swing", "javax.swing", "java.applet", "java.beans",
			"java.rmi", "java.util.concurrent", "java.util.regex", "java.util.zip",
		},
		LanguageC: {
			"stdio.h", "stdlib.h", "string.h", "math.h", "time.h", "ctype.h",
			"limits.h", "float.h", "stdarg.h", "stddef.h", "errno.h", "assert.h",
			"locale.h", "setjmp.h", "signal.h", "stdint.h", "inttypes.h",
			"stdbool.h", "complex.h", "fenv.h", "iso646.h", "tgmath.h",
			"wchar.h", "wctype.h",
		},
		LanguageCPP: {
			"iostream", "vector", "string", "algorithm", "map", "set", "list",
			"queue", "stack", "deque", "array", "unordered_map", "unordered_set",
			"memory", "utility", "functional", "iterator", "numeric", "random",
			"chrono", "thread", "mutex", "condition_variable", "atomic", "future",
			"regex", "fstream", "sstream", "iomanip", "exception", "stdexcept",
			"typeinfo", "type_traits", "limits", "cmath", "cstdlib", "cstring",
		},
		LanguageCSharp: {
			"System", "System.Collections", "System.Collections.Generic",
			"System.IO", "System.Net", "System.Text", "System.Threading",
			"System.Threading.Tasks", "System.Linq", "System.Xml", "System.Json",
			"System.Security", "System.Reflection", "System.Runtime",
			"System.Diagnostics", "System.ComponentModel", "System.Drawing",
			"System.Windows", "Microsoft.Extensions", "System.Data",
		},
	}
}

// getStandardLibraries returns standard library module mappings
func getStandardLibraries() map[Language]map[string]bool {
	result := make(map[Language]map[string]bool)
	
	builtInModules := getBuiltInModules()
	for lang, modules := range builtInModules {
		moduleMap := make(map[string]bool)
		for _, module := range modules {
			moduleMap[module] = true
		}
		result[lang] = moduleMap
	}
	
	return result
}

// getPythonStandardLibrary returns Python standard library modules
func getPythonStandardLibrary() map[string]bool {
	modules := []string{
		// Core modules
		"__future__", "__main__", "_thread", "abc", "aifc", "argparse", "array",
		"ast", "asynchat", "asyncio", "asyncore", "atexit", "audioop", "base64",
		"bdb", "binascii", "binhex", "bisect", "builtins", "bz2", "calendar",
		"cgi", "cgitb", "chunk", "cmath", "cmd", "code", "codecs", "codeop",
		"collections", "colorsys", "compileall", "concurrent", "configparser",
		"contextlib", "copy", "copyreg", "crypt", "csv", "ctypes", "curses",
		"dataclasses", "datetime", "dbm", "decimal", "difflib", "dis", "distutils",
		"doctest", "email", "encodings", "enum", "errno", "faulthandler", "fcntl",
		"filecmp", "fileinput", "fnmatch", "formatter", "fractions", "ftplib",
		"functools", "gc", "getopt", "getpass", "gettext", "glob", "gzip",
		"hashlib", "heapq", "hmac", "html", "http", "imaplib", "imghdr", "imp",
		"importlib", "inspect", "io", "ipaddress", "itertools", "json", "keyword",
		"lib2to3", "linecache", "locale", "logging", "lzma", "mailbox", "mailcap",
		"marshal", "math", "mimetypes", "mmap", "modulefinder", "multiprocessing",
		"netrc", "nntplib", "numbers", "operator", "optparse", "os", "ossaudiodev",
		"parser", "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil",
		"platform", "plistlib", "poplib", "posix", "pprint", "profile", "pstats",
		"pty", "pwd", "py_compile", "pyclbr", "pydoc", "queue", "quopri", "random",
		"re", "readline", "reprlib", "resource", "rlcompleter", "runpy", "sched",
		"secrets", "select", "selectors", "shelve", "shlex", "shutil", "signal",
		"site", "smtpd", "smtplib", "sndhdr", "socket", "socketserver", "sqlite3",
		"ssl", "stat", "statistics", "string", "stringprep", "struct", "subprocess",
		"sunau", "symbol", "symtable", "sys", "sysconfig", "tabnanny", "tarfile",
		"telnetlib", "tempfile", "termios", "test", "textwrap", "threading", "time",
		"timeit", "tkinter", "token", "tokenize", "trace", "traceback", "tracemalloc",
		"tty", "turtle", "types", "typing", "unicodedata", "unittest", "urllib",
		"uu", "uuid", "venv", "warnings", "wave", "weakref", "webbrowser",
		"winreg", "winsound", "wsgiref", "xdrlib", "xml", "xmlrpc", "zipapp",
		"zipfile", "zipimport", "zlib",
	}

	result := make(map[string]bool)
	for _, module := range modules {
		result[module] = true
	}
	return result
}

// getJavaScriptBuiltins returns JavaScript/Node.js built-in modules
func getJavaScriptBuiltins() map[string]bool {
	modules := []string{
		// Node.js core modules
		"assert", "async_hooks", "buffer", "child_process", "cluster", "console",
		"constants", "crypto", "dgram", "dns", "domain", "events", "fs", "http",
		"http2", "https", "inspector", "module", "net", "os", "path", "perf_hooks",
		"process", "punycode", "querystring", "readline", "repl", "stream",
		"string_decoder", "timers", "tls", "trace_events", "tty", "url", "util",
		"v8", "vm", "worker_threads", "zlib",
		
		// Browser globals
		"window", "document", "console", "navigator", "location", "history",
		"localStorage", "sessionStorage", "XMLHttpRequest", "fetch", "Promise",
		"Map", "Set", "WeakMap", "WeakSet", "Proxy", "Reflect", "Symbol",
		"ArrayBuffer", "DataView", "Int8Array", "Uint8Array", "Int16Array",
		"Uint16Array", "Int32Array", "Uint32Array", "Float32Array", "Float64Array",
	}

	result := make(map[string]bool)
	for _, module := range modules {
		result[module] = true
	}
	return result
}

// getGoStandardLibrary returns Go standard library packages
func getGoStandardLibrary() map[string]bool {
	packages := []string{
		"archive/tar", "archive/zip", "bufio", "builtin", "bytes", "compress/bzip2",
		"compress/flate", "compress/gzip", "compress/lzw", "compress/zlib",
		"container/heap", "container/list", "container/ring", "context", "crypto",
		"crypto/aes", "crypto/cipher", "crypto/des", "crypto/dsa", "crypto/ecdsa",
		"crypto/elliptic", "crypto/hmac", "crypto/md5", "crypto/rand", "crypto/rc4",
		"crypto/rsa", "crypto/sha1", "crypto/sha256", "crypto/sha512", "crypto/subtle",
		"crypto/tls", "crypto/x509", "database/sql", "database/sql/driver", "debug/dwarf",
		"debug/elf", "debug/gosym", "debug/macho", "debug/pe", "debug/plan9obj",
		"encoding", "encoding/ascii85", "encoding/asn1", "encoding/base32",
		"encoding/base64", "encoding/binary", "encoding/csv", "encoding/gob",
		"encoding/hex", "encoding/json", "encoding/pem", "encoding/xml", "errors",
		"expvar", "flag", "fmt", "go/ast", "go/build", "go/constant", "go/doc",
		"go/format", "go/importer", "go/parser", "go/printer", "go/scanner",
		"go/token", "go/types", "hash", "hash/adler32", "hash/crc32", "hash/crc64",
		"hash/fnv", "html", "html/template", "image", "image/color", "image/draw",
		"image/gif", "image/jpeg", "image/png", "index/suffixarray", "io",
		"io/ioutil", "log", "log/syslog", "math", "math/big", "math/bits",
		"math/cmplx", "math/rand", "mime", "mime/multipart", "mime/quotedprintable",
		"net", "net/http", "net/mail", "net/rpc", "net/smtp", "net/textproto",
		"net/url", "os", "os/exec", "os/signal", "os/user", "path", "path/filepath",
		"plugin", "reflect", "regexp", "regexp/syntax", "runtime", "runtime/debug",
		"runtime/pprof", "runtime/race", "runtime/trace", "sort", "strconv",
		"strings", "sync", "sync/atomic", "syscall", "testing", "testing/iotest",
		"testing/quick", "text/scanner", "text/tabwriter", "text/template",
		"text/template/parse", "time", "unicode", "unicode/utf16", "unicode/utf8",
		"unsafe",
	}

	result := make(map[string]bool)
	for _, pkg := range packages {
		result[pkg] = true
	}
	return result
}