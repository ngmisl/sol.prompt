package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	ProjectName    = "sol.prompt"
	MaxFileSize    = 50 * 1024 * 1024 // 50MB limit
	MaxConcurrency = 8
	TokenLimit     = 100000 // Rough token estimate for LLM context
)

// Enhanced type system for better categorization
type SecurityLevel uint8

const (
	SecurityCritical SecurityLevel = iota // Financial operations, access control
	SecurityHigh                          // State changes, user interactions
	SecurityMedium                        // View functions, events
	SecurityLow                           // Pure functions, constants
)

func (s SecurityLevel) String() string {
	return [...]string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}[s]
}

type FunctionCategory uint8

const (
	CategoryUnknown   FunctionCategory = iota
	CategoryFinancial                  // Transfer, mint, burn, withdraw
	CategoryAccess                     // Owner, admin, role management
	CategoryState                      // State changing operations
	CategoryView                       // Read-only functions
	CategoryUtility                    // Helper functions
)

func (f FunctionCategory) String() string {
	return [...]string{"UNKNOWN", "FINANCIAL", "ACCESS", "STATE", "VIEW", "UTILITY"}[f]
}

// Enhanced visibility with more granular control
type Visibility uint8

const (
	VisibilityPrivate Visibility = iota
	VisibilityInternal
	VisibilityPublic
	VisibilityExternal
)

func (v Visibility) String() string {
	return [...]string{"private", "internal", "public", "external"}[v]
}

func (v Visibility) IsUserFacing() bool {
	return v == VisibilityPublic || v == VisibilityExternal
}

func (v Visibility) RiskScore() int {
	return [...]int{1, 2, 4, 5}[v] // Higher scores for more exposed functions
}

// Enhanced element types with better categorization
type ElementType uint8

const (
	ElementUnknown ElementType = iota
	ElementPragma
	ElementImport
	ElementContract
	ElementInterface
	ElementLibrary
	ElementFunction
	ElementModifier
	ElementEvent
	ElementError
	ElementStruct
	ElementEnum
	ElementStateVariable
	ElementMapping
	ElementConstructor
	ElementReceive
	ElementFallback
	ElementUsing
)

func (et ElementType) String() string {
	if et > ElementUsing { // Check bounds to prevent panic on out-of-range values
		return fmt.Sprintf("ElementType(%d)", et)
	}
	return [...]string{
		"UnknownElement",
		"Pragma",
		"Import",
		"Contract",
		"Interface",
		"Library",
		"Function",
		"Modifier",
		"Event",
		"ErrorDefinition", // Solidity custom error definition
		"Struct",
		"Enum",
		"StateVariable",
		"Mapping",
		"Constructor",
		"Receive",
		"Fallback",
		"UsingDirective",
	}[et]
}

// Comprehensive audit configuration
type AuditConfig struct {
	IncludePrivate      bool
	IncludeComments     bool
	IncludeTestImports  bool
	MaxTokens           int
	SecurityFocus       bool
	IncludeDependencies bool
	GenerateCallGraph   bool
	RiskAnalysis        bool
	OptimizeForModel    string // "gpt", "claude", "generic"
}

func NewOptimizedAuditConfig() AuditConfig {
	return AuditConfig{
		IncludePrivate:      false,
		IncludeComments:     true, // Keep security-relevant comments
		IncludeTestImports:  false,
		MaxTokens:           TokenLimit,
		SecurityFocus:       true,
		IncludeDependencies: true,
		GenerateCallGraph:   true,
		RiskAnalysis:        true,
		OptimizeForModel:    "generic",
	}
}

// Enhanced error types for better diagnostics
type ProcessingError struct {
	File        string
	Line        int
	Column      int
	Element     ElementType
	Severity    string
	Err         error
	Recoverable bool
}

func (e *ProcessingError) Error() string {
	return fmt.Sprintf("[%s] %s:%d:%d - %s: %v", e.Severity, e.File, e.Line, e.Column, e.Element, e.Err)
}

// Enhanced code element with security analysis
type CodeElement struct {
	Type          ElementType
	Content       string
	CleanContent  string
	Visibility    Visibility
	LineNumber    int
	IsComplete    bool
	SecurityLevel SecurityLevel
	Category      FunctionCategory
	Metadata      map[string]any
	Dependencies  []string
	CalledBy      []string
	Modifiers     []string
	RiskFactors   []string
	TokenEstimate int
}

// Function signature analysis
type FunctionSignature struct {
	Name       string
	Parameters []Parameter
	Returns    []Parameter
	Modifiers  []string
	Payable    bool
	StateMut   string // pure, view, payable, nonpayable
}

type Parameter struct {
	Type string
	Name string
}

// Enhanced contract analysis
type ContractFile struct {
	Path           string
	Name           string
	Hash           string
	Elements       []CodeElement
	Size           int64
	Functions      map[string]*FunctionSignature
	StateVars      []string
	Events         []string
	Errors         []string
	Inheritance    []string
	Dependencies   []string
	RiskScore      int
	TokenCount     int
	ProcessingTime time.Duration
}

// Comprehensive audit result with analytics
type AuditResult struct {
	Files           []ContractFile
	ProcessedAt     time.Time
	TotalLines      int
	FilteredLines   int
	Config          AuditConfig
	Summary         AuditSummary
	CallGraph       map[string][]string
	RiskAnalysis    RiskAnalysis
	Recommendations []string
	EstimatedTokens int
}

type AuditSummary struct {
	TotalContracts    int
	FilesAttempted    int64 // Number of files attempted for processing
	LinesProcessed    int64 // Total lines processed across all files
	RecoveredErrors   int64 // Number of errors recovered during processing
	PublicFunctions   int
	CriticalFunctions int
	StateVariables    int
	Events            int
	UniqueErrors      int
	ExternalCalls     int
	HighRiskPatterns  []string
}

type RiskAnalysis struct {
	CriticalFindings []string
	HighRiskFindings []string
	Patterns         map[string]int
	Recommendations  []string
}

// Resilient processor with recovery capabilities
type ResilientSolidityProcessor struct {
	patterns         map[ElementType]*regexp.Regexp
	securityPatterns map[string]SecurityLevel
	categoryPatterns map[string]FunctionCategory
	tokenizer        *token.FileSet
	mu               sync.RWMutex
	stats            ProcessingStats
}

type ProcessingStats struct {
	FilesProcessed  int64
	LinesProcessed  int64
	ErrorsRecovered int64
	TokensEstimated int64
}

func NewResilientProcessor() *ResilientSolidityProcessor {
	processor := &ResilientSolidityProcessor{
		patterns: map[ElementType]*regexp.Regexp{
			ElementPragma:        regexp.MustCompile(`^\s*pragma\s+([^;]+);?`),
			ElementImport:        regexp.MustCompile(`^\s*import\s+(.+);`),
			ElementContract:      regexp.MustCompile(`^\s*(abstract\s+)?(contract|interface|library)\s+(\w+)(\s+is\s+([^{]+))?`),
			ElementFunction:      regexp.MustCompile(`^\s*function\s+(\w+)\s*\([^)]*\)([^{;]*)[{;]`),
			ElementConstructor:   regexp.MustCompile(`^\s*constructor\s*\([^)]*\)([^{]*)`),
			ElementModifier:      regexp.MustCompile(`^\s*modifier\s+(\w+)\s*(\([^)]*\))?([^{]*)`),
			ElementEvent:         regexp.MustCompile(`^\s*event\s+(\w+)\s*\([^)]*\);?`),
			ElementError:         regexp.MustCompile(`^\s*error\s+(\w+)\s*(\([^)]*\))?;?`),
			ElementStruct:        regexp.MustCompile(`^\s*struct\s+(\w+)\s*{`),
			ElementEnum:          regexp.MustCompile(`^\s*enum\s+(\w+)\s*{`),
			ElementStateVariable: regexp.MustCompile(`^\s*(mapping\s*\([^)]+\)|uint\d*|int\d*|bool|address|string|bytes\d*)\s+(\w+)`),
			ElementMapping:       regexp.MustCompile(`^\s*mapping\s*\([^)]+\)\s*(\w+)`),
			ElementReceive:       regexp.MustCompile(`^\s*receive\s*\(\s*\)\s*external\s+payable`),
			ElementFallback:      regexp.MustCompile(`^\s*fallback\s*\([^)]*\)\s*external`),
			ElementUsing:         regexp.MustCompile(`^\s*using\s+(\w+)\s+for\s+([^;]+);`),
		},
		securityPatterns: map[string]SecurityLevel{
			"transfer":     SecurityCritical,
			"withdraw":     SecurityCritical,
			"mint":         SecurityCritical,
			"burn":         SecurityCritical,
			"approve":      SecurityCritical,
			"transferFrom": SecurityCritical,
			"selfdestruct": SecurityCritical,
			"delegatecall": SecurityCritical,
			"call":         SecurityHigh,
			"send":         SecurityHigh,
			"onlyOwner":    SecurityHigh,
			"onlyAdmin":    SecurityHigh,
			"require":      SecurityMedium,
			"assert":       SecurityMedium,
			"view":         SecurityLow,
			"pure":         SecurityLow,
		},
		categoryPatterns: map[string]FunctionCategory{
			"transfer|withdraw|deposit|mint|burn|approve": CategoryFinancial,
			"owner|admin|role|access|auth":                CategoryAccess,
			"set|update|change|modify":                    CategoryState,
			"get|view|read|check":                         CategoryView,
			"_|internal|helper":                           CategoryUtility,
		},
		tokenizer: token.NewFileSet(),
	}
	return processor
}

var spaceRegex = regexp.MustCompile(`\s+`)

func (rsp *ResilientSolidityProcessor) ProcessLine(line string, lineNum int, fileName string) (CodeElement, *ProcessingError) {
	defer func() {
		if r := recover(); r != nil {
			// Log panic but continue processing
			fmt.Printf("Recovered from panic in %s:%d: %v\n", fileName, lineNum, r)
		}
	}()

	rsp.mu.Lock()
	rsp.stats.LinesProcessed++
	rsp.mu.Unlock()

	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "//") {
		return CodeElement{Type: ElementUnknown}, nil
	}

	element := CodeElement{
		Content:       line,
		CleanContent:  rsp.cleanLine(trimmed),
		LineNumber:    lineNum,
		IsComplete:    true,
		Metadata:      make(map[string]any),
		TokenEstimate: rsp.estimateTokens(line),
	}

	// Pattern matching with error recovery
	matched := false
	for elemType, pattern := range rsp.patterns {
		if matches := pattern.FindStringSubmatch(trimmed); matches != nil {
			element.Type = elemType
			element = rsp.enrichElement(element, matches, trimmed)
			matched = true
			break
		}
	}

	if !matched {
		// Try to infer type from context
		element.Type = rsp.inferElementType(trimmed)
	}

	// Security and category analysis
	element.SecurityLevel = rsp.analyzeSecurityLevel(trimmed)
	element.Category = rsp.analyzeCategory(trimmed)
	element.RiskFactors = rsp.identifyRiskFactors(trimmed)

	return element, nil
}

func (rsp *ResilientSolidityProcessor) cleanLine(line string) string {
	cleanedLine := line // Assume line is kept as is, unless a non-special comment is found

	if idx := strings.Index(line, "//"); idx != -1 {
		// Found a "//"
		commentContent := line[idx+2:] // Text after "//"

		// Trim leading whitespace from the comment content itself
		trimmedCommentText := strings.TrimLeft(commentContent, " \t")

		// Check if the trimmed comment content starts with '@' or '/'
		isSpecialComment := false
		if len(trimmedCommentText) > 0 {
			if trimmedCommentText[0] == '@' || trimmedCommentText[0] == '/' {
				isSpecialComment = true
			}
		}

		if !isSpecialComment {
			// It's a normal comment, so remove it.
			// The cleaned line is the part before the comment, with trailing spaces trimmed from the code part.
			cleanedLine = strings.TrimRight(line[:idx], " \t")
		}
		// If it's a special comment, cleanedLine remains the original 'line', so the comment is preserved.
	}

	// Normalize whitespace on the potentially modified line
	// Trim leading/trailing whitespace from the entire line first, then replace multiple spaces with a single space.
	finalCleaned := spaceRegex.ReplaceAllString(strings.TrimSpace(cleanedLine), " ")

	return finalCleaned
}

func (rsp *ResilientSolidityProcessor) estimateTokens(text string) int {
	// Rough GPT tokenization estimate: ~4 chars per token
	return len(text) / 4
}

func (rsp *ResilientSolidityProcessor) enrichElement(element CodeElement, matches []string, line string) CodeElement {
	switch element.Type {
	case ElementContract, ElementInterface, ElementLibrary:
		if len(matches) > 3 {
			element.Metadata["name"] = matches[3]
			if len(matches) > 5 && matches[5] != "" {
				element.Metadata["inheritance"] = strings.Split(matches[5], ",")
			}
		}
	case ElementFunction:
		element.Visibility = extractVisibility(line)
		element.Metadata["name"] = matches[1]
		element.Metadata["signature"] = rsp.extractFunctionSignature(line)
		element.Modifiers = rsp.extractModifiers(line)
	case ElementStateVariable:
		element.Visibility = extractVisibility(line)
		if len(matches) > 2 {
			element.Metadata["name"] = matches[2]
			element.Metadata["type"] = matches[1]
		}
	}
	return element
}

func (rsp *ResilientSolidityProcessor) inferElementType(line string) ElementType {
	line = strings.ToLower(line)

	if strings.Contains(line, "function") {
		return ElementFunction
	}
	if strings.Contains(line, "event") {
		return ElementEvent
	}
	if strings.Contains(line, "modifier") {
		return ElementModifier
	}

	return ElementUnknown
}

func (rsp *ResilientSolidityProcessor) analyzeSecurityLevel(line string) SecurityLevel {
	line = strings.ToLower(line)

	for pattern, level := range rsp.securityPatterns {
		if strings.Contains(line, pattern) {
			return level
		}
	}

	// Additional heuristics
	if strings.Contains(line, "payable") || strings.Contains(line, "ether") {
		return SecurityCritical
	}
	if strings.Contains(line, "external") || strings.Contains(line, "public") {
		return SecurityHigh
	}

	return SecurityLow
}

func (rsp *ResilientSolidityProcessor) analyzeCategory(line string) FunctionCategory {
	line = strings.ToLower(line)

	for pattern, category := range rsp.categoryPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			return category
		}
	}

	return CategoryUnknown
}

func (rsp *ResilientSolidityProcessor) identifyRiskFactors(line string) []string {
	var risks []string
	line = strings.ToLower(line)

	riskPatterns := map[string]string{
		"delegatecall":    "Dangerous delegatecall usage",
		"tx.origin":       "tx.origin authentication vulnerability",
		"block.timestamp": "Block timestamp manipulation risk",
		"block.number":    "Block number dependency",
		"selfdestruct":    "Contract destruction capability",
		"assembly":        "Inline assembly usage",
		"unchecked":       "Unchecked arithmetic operations",
		"call.value":      "Direct call with value transfer",
	}

	for pattern, risk := range riskPatterns {
		if strings.Contains(line, pattern) {
			risks = append(risks, risk)
		}
	}

	return risks
}

func (rsp *ResilientSolidityProcessor) extractFunctionSignature(line string) string {
	// Extract complete function signature
	funcRegex := regexp.MustCompile(`function\s+(\w+)\s*\([^)]*\)([^{;]*)`)
	if matches := funcRegex.FindStringSubmatch(line); matches != nil {
		return strings.TrimSpace(matches[0])
	}
	return ""
}

func (rsp *ResilientSolidityProcessor) extractModifiers(line string) []string {
	var modifiers []string

	// Common modifiers
	modifierPatterns := []string{
		`onlyOwner`, `onlyAdmin`, `whenNotPaused`, `nonReentrant`,
		`validAddress`, `notZero`, `initialized`,
	}

	for _, pattern := range modifierPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			modifiers = append(modifiers, pattern)
		}
	}

	return modifiers
}

func extractVisibility(line string) Visibility {
	switch {
	case strings.Contains(line, "public"):
		return VisibilityPublic
	case strings.Contains(line, "external"):
		return VisibilityExternal
	case strings.Contains(line, "internal"):
		return VisibilityInternal
	case strings.Contains(line, "private"):
		return VisibilityPrivate
	default:
		return VisibilityInternal
	}
}

// Concurrent file processing with worker pools
func processFilesConcurrently(ctx context.Context, filePaths []string, processor *ResilientSolidityProcessor, config AuditConfig) ([]ContractFile, error) {
	filesChan := make(chan string, len(filePaths))
	resultsChan := make(chan ContractFile, len(filePaths))
	errorsChan := make(chan error, len(filePaths))

	// Limit concurrency
	numWorkers := min(MaxConcurrency, runtime.NumCPU())
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range filesChan {
				select {
				case <-ctx.Done():
					return
				default:
					if file, err := processFile(ctx, filePath, processor, config); err != nil {
						errorsChan <- err
					} else {
						resultsChan <- file
					}
				}
			}
		}()
	}

	// Send files to workers
	go func() {
		for _, path := range filePaths {
			filesChan <- path
		}
		close(filesChan)
	}()

	// Wait for completion
	go func() {
		wg.Wait()
		close(resultsChan)
		close(errorsChan)
	}()

	// Collect results
	var files []ContractFile
	var errors []error

	for {
		select {
		case file, ok := <-resultsChan:
			if !ok {
				resultsChan = nil
			} else {
				files = append(files, file)
			}
		case err, ok := <-errorsChan:
			if !ok {
				errorsChan = nil
			} else {
				errors = append(errors, err)
			}
		}

		if resultsChan == nil && errorsChan == nil {
			break
		}
	}

	// Report errors but continue
	for _, err := range errors {
		fmt.Printf("Processing error: %v\n", err)
	}

	return files, nil
}

func processFile(ctx context.Context, filePath string, processor *ResilientSolidityProcessor, config AuditConfig) (ContractFile, error) {
	startTime := time.Now()

	// File size validation
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return ContractFile{}, fmt.Errorf("failed to stat file %s: %w", filePath, err)
	}

	if fileInfo.Size() > MaxFileSize {
		return ContractFile{}, fmt.Errorf("file %s too large: %d bytes", filePath, fileInfo.Size())
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return ContractFile{}, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Generate file hash for integrity
	hash := sha256.Sum256(content)

	lines := strings.Split(string(content), "\n")
	var elements []CodeElement
	var errorCount int

	fileName := filepath.Base(filePath)

	for i, line := range lines {
		select {
		case <-ctx.Done():
			return ContractFile{}, ctx.Err()
		default:
		}

		element, procErr := processor.ProcessLine(line, i+1, fileName)

		if procErr != nil {
			errorCount++
			if !procErr.Recoverable {
				fmt.Printf("Unrecoverable error in %s: %v\n", filePath, procErr)
				continue
			}
		}

		if shouldIncludeElement(element, config) {
			elements = append(elements, element)
		}
	}

	file := ContractFile{
		Path:           filePath,
		Name:           fileName,
		Hash:           hex.EncodeToString(hash[:]),
		Elements:       elements,
		Size:           fileInfo.Size(),
		Functions:      make(map[string]*FunctionSignature),
		ProcessingTime: time.Since(startTime),
	}

	// Post-processing analysis
	file = analyzeContract(file)

	processor.mu.Lock()
	processor.stats.FilesProcessed++
	processor.stats.ErrorsRecovered += int64(errorCount)
	processor.mu.Unlock()

	return file, nil
}

func shouldIncludeElement(element CodeElement, config AuditConfig) bool {
	if element.Type == ElementUnknown {
		return false
	}

	// Always include high-security elements
	if element.SecurityLevel == SecurityCritical {
		return true
	}

	// Include based on visibility and configuration
	if element.Visibility.IsUserFacing() {
		return true
	}

	if config.IncludePrivate && element.Visibility == VisibilityPrivate {
		return true
	}

	// Include important structural elements
	importantTypes := []ElementType{
		ElementPragma, ElementContract, ElementInterface, ElementLibrary,
		ElementEvent, ElementError, ElementModifier, ElementConstructor,
		ElementStateVariable, ElementMapping,
	}

	return slices.Contains(importantTypes, element.Type)
}

func analyzeContract(file ContractFile) ContractFile {
	// Extract function signatures and analyze relationships
	for _, element := range file.Elements {
		if element.Type == ElementFunction {
			if name, ok := element.Metadata["name"].(string); ok {
				file.Functions[name] = &FunctionSignature{
					Name:      name,
					Modifiers: element.Modifiers,
				}
			}
		}
	}

	// Calculate risk score
	file.RiskScore = calculateRiskScore(file)

	// Estimate token count
	tokenCount := 0
	for _, element := range file.Elements {
		tokenCount += element.TokenEstimate
	}
	file.TokenCount = tokenCount

	return file
}

func calculateRiskScore(file ContractFile) int {
	score := 0

	for _, element := range file.Elements {
		score += int(element.SecurityLevel) * element.Visibility.RiskScore()
		score += len(element.RiskFactors) * 5
	}

	return score
}

// Optimized LLM output generation - now generates XML
func generateOptimizedOutput(result AuditResult) string {
	var builder strings.Builder
	// Estimate size: ~50 chars per contract for tags + total estimated tokens for content
	// Add a buffer for CDATA tags and newlines.
	builder.Grow(len(result.Files)*100 + result.EstimatedTokens*2) // Adjusted pre-allocation for XML

	builder.WriteString("<contracts>\n")

	for _, file := range result.Files {
		builder.WriteString(fmt.Sprintf("  <contract name=\"%s\">\n", escapeXML(file.Name)))
		builder.WriteString("    <![CDATA[\n")

		// Concatenate content of all elements for this file
		// We'll use the original order of elements as they appear in the file.
		// The `file.Elements` should already be in the correct order from parsing.
		var contractContentBuilder strings.Builder
		for _, element := range file.Elements {
			// We can include the annotations if they are helpful for the LLM
			// For now, let's stick to the raw element.Content as per previous findings.
			// If annotations are needed, the logic from writeElements can be adapted here.
			contractContentBuilder.WriteString(element.Content)
			contractContentBuilder.WriteString("\n") // Add a newline between elements for readability
		}
		builder.WriteString(strings.TrimSpace(contractContentBuilder.String()))
		builder.WriteString("\n    ]]>\n")
		builder.WriteString("  </contract>\n")
	}

	builder.WriteString("</contracts>")

	return builder.String()
}

// escapeXML is a helper function to escape characters that have special meaning in XML.
// Added to support filenames or other attributes that might contain such characters.
func escapeXML(s string) string {
	var esc strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			esc.WriteString("&amp;")
		case '<':
			esc.WriteString("&lt;")
		case '>':
			esc.WriteString("&gt;")
		case '\'':
			esc.WriteString("&apos;")
		case '"':
			esc.WriteString("&quot;")
		default:
			esc.WriteRune(r)
		}
	}
	return esc.String()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <solidity_folder_path> [--include-private] [--security-focus]\n", ProjectName)
		os.Exit(1)
	}

	folderPath := os.Args[1]
	config := NewOptimizedAuditConfig()

	// Parse command line arguments
	for _, arg := range os.Args[2:] {
		switch arg {
		case "--include-private":
			config.IncludePrivate = true
		case "--security-focus":
			config.SecurityFocus = true
		case "--include-test":
			config.IncludeTestImports = true
		case "--optimize-gpt":
			config.OptimizeForModel = "gpt"
		case "--optimize-claude":
			config.OptimizeForModel = "claude"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	fmt.Printf("🔍 %s - Smart Contract Security Audit Preparation\n", ProjectName)
	fmt.Printf("📁 Analyzing: %s\n", folderPath)

	// Discover Solidity files
	var filePaths []string
	err := filepath.WalkDir(folderPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(path), ".sol") {
			filePaths = append(filePaths, path)
		}
		return nil
	})

	if err != nil {
		fmt.Printf("❌ Error walking directory: %v\n", err)
		os.Exit(1)
	}

	if len(filePaths) == 0 {
		fmt.Println("❌ No Solidity files found")
		os.Exit(1)
	}

	fmt.Printf("📄 Found %d Solidity files\n", len(filePaths))

	// Process files concurrently
	processor := NewResilientProcessor()
	files, err := processFilesConcurrently(ctx, filePaths, processor, config)
	if err != nil {
		fmt.Printf("❌ Processing error: %v\n", err)
		os.Exit(1)
	}

	// Generate comprehensive audit result
	auditResult := generateAuditResult(files, config, processor.stats)

	// Generate optimized output
	output := generateOptimizedOutput(auditResult)

	// Write to sol.prompt
	if err := os.WriteFile(ProjectName, []byte(output), 0644); err != nil {
		fmt.Printf("❌ Error writing %s: %v\n", ProjectName, err)
		os.Exit(1)
	}

	// Success metrics
	fmt.Printf("✅ Successfully generated %s\n", ProjectName)
	fmt.Printf("📊 Statistics:\n")
	fmt.Printf("   - Files processed: %d\n", len(files))
	fmt.Printf("   - Critical functions: %d\n", auditResult.Summary.CriticalFunctions)
	fmt.Printf("   - Estimated tokens: %d\n", auditResult.EstimatedTokens)
	fmt.Printf("   - Risk patterns found: %d\n", len(auditResult.Summary.HighRiskPatterns))

	if auditResult.EstimatedTokens > TokenLimit {
		fmt.Printf("⚠️  Warning: Output may exceed LLM context limits (%d tokens)\n", TokenLimit)
	}
}

func generateAuditResult(files []ContractFile, config AuditConfig, stats ProcessingStats) AuditResult {
	summary := AuditSummary{
		TotalContracts: len(files),
		FilesAttempted: stats.FilesProcessed,
		LinesProcessed: stats.LinesProcessed,
		RecoveredErrors: stats.ErrorsRecovered,
	}

	var totalTokens int
	var criticalFindings []string

	for _, file := range files {
		totalTokens += file.TokenCount

		for _, element := range file.Elements {
			if element.Visibility.IsUserFacing() {
				if element.Type == ElementFunction {
					summary.PublicFunctions++
				}
			}

			if element.SecurityLevel == SecurityCritical {
				summary.CriticalFunctions++
			}

			if len(element.RiskFactors) > 0 {
				criticalFindings = append(criticalFindings, element.RiskFactors...)
			}
		}
	}

	// Deduplicate findings
	summary.HighRiskPatterns = deduplicateStrings(criticalFindings)

	return AuditResult{
		Files:           files,
		ProcessedAt:     time.Now(),
		TotalLines:      int(stats.LinesProcessed),
		FilteredLines:   0,                       // TODO: Populate this if applicable
		Config:          config,
		Summary:         summary,
		CallGraph:       nil, // TODO: Populate this if applicable
		RiskAnalysis: RiskAnalysis{
			CriticalFindings: summary.HighRiskPatterns,
		},
		Recommendations: nil, // TODO: Populate this if applicable
		EstimatedTokens: totalTokens,
	}
}

func deduplicateStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
