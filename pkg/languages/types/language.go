package types

// Language represents a supported programming language
type Language string

const (
	LanguagePython     Language = "python"
	LanguageJavaScript Language = "javascript"
	LanguageTypeScript Language = "typescript"
	LanguageGo         Language = "go"
	LanguageRust       Language = "rust"
	LanguageJava       Language = "java"
	LanguageC          Language = "c"
	LanguageCPP        Language = "cpp"
	LanguageCSharp     Language = "csharp"
	LanguageRuby       Language = "ruby"
	LanguagePHP        Language = "php"
	LanguageShell      Language = "shell"
	LanguageR          Language = "r"
	LanguageLua        Language = "lua"
	LanguagePerl       Language = "perl"
)

// String returns the string representation of the language
func (l Language) String() string {
	return string(l)
}

// IsValid checks if the language is a valid supported language
func (l Language) IsValid() bool {
	switch l {
	case LanguagePython, LanguageJavaScript, LanguageTypeScript, LanguageGo,
		LanguageRust, LanguageJava, LanguageC, LanguageCPP, LanguageCSharp,
		LanguageRuby, LanguagePHP, LanguageShell, LanguageR, LanguageLua, LanguagePerl:
		return true
	default:
		return false
	}
}

// GetAllLanguages returns a slice of all supported languages
func GetAllLanguages() []Language {
	return []Language{
		LanguagePython, LanguageJavaScript, LanguageTypeScript, LanguageGo,
		LanguageRust, LanguageJava, LanguageC, LanguageCPP, LanguageCSharp,
		LanguageRuby, LanguagePHP, LanguageShell, LanguageR, LanguageLua, LanguagePerl,
	}
}