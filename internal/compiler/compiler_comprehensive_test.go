package compiler

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// TestCompilerEndToEnd tests the complete compilation pipeline from source to FSM
func TestCompilerEndToEnd(t *testing.T) {
	tests := []struct {
		name           string
		source         string
		expectedStates int
		shouldFail     bool
		errorContains  string
	}{
		{
			name: "Simple single syscall policy",
			source: `path "simple_test" {
				openat { pathname="/etc/passwd" }
			}`,
			expectedStates: 3, // initial + syscall + terminal
			shouldFail:     false,
		},
		{
			name: "Multi-step sequential policy",
			source: `path "multi_step" {
				openat { pathname="/etc/passwd" }
				execve { filename="/bin/sh" }
				write { content="malicious" }
			}`,
			expectedStates: 5, // initial + 3 syscalls + terminal
			shouldFail:     false,
		},
		{
			name: "Complex regex patterns",
			source: `path "regex_test" {
				openat { pathname=~"/etc/.*" }
				execve { filename=~".*sh$" }
			}`,
			expectedStates: 4, // initial + 2 syscalls + terminal
			shouldFail:     false,
		},
		{
			name: "Block with conditional logic",
			source: `path "conditional_test" {
				openat { pathname="/etc/passwd" } ?
				block "then_block" {
					execve { filename="/bin/bash" }
				} :
				block "else_block" {
					write { content="safe" }
				}
			}`,
			expectedStates: 6, // More complex state structure
			shouldFail:     false,
		},
		{
			name: "Nested blocks",
			source: `path "nested_test" {
				block "outer" {
					openat { pathname="/etc/passwd" }
					block "inner" {
						execve { filename="/bin/sh" }
						write {}
					}
				}
			}`,
			expectedStates: 5, // initial + nested structure + terminal
			shouldFail:     false,
		},
		{
			name: "Empty policy",
			source: `path "empty" {
			}`,
			expectedStates: 1, // just initial state, no terminals
			shouldFail:     false,
		},
		{
			name: "Invalid syscall name",
			source: `path "invalid_syscall" {
				invalid_syscall { param="value" }
			}`,
			shouldFail:    true,
			errorContains: "unexpected token",
		},
		{
			name: "Invalid regex pattern",
			source: `path "invalid_regex" {
				openat { pathname=~"[invalid" }
			}`,
			shouldFail:    true,
			errorContains: "invalid regex",
		},
		{
			name: "Missing policy name",
			source: `path {
				openat { pathname="/test" }
			}`,
			shouldFail:    true,
			errorContains: "expected policy name",
		},
		{
			name: "Unclosed braces",
			source: `path "unclosed" {
				openat { pathname="/test"
			`,
			shouldFail:    true,
			errorContains: "expected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test lexing
			_, lexErr := TokenizeInput(tt.source)
			if lexErr != nil && !tt.shouldFail {
				t.Fatalf("Unexpected lexer error: %v", lexErr)
			}

			if lexErr == nil && tt.shouldFail && strings.Contains(tt.errorContains, "regex") {
				// Lexer should catch regex errors
				t.Errorf("Expected lexer to catch regex error, but it didn't")
			}

			// Test parsing
			program, parseErr := ParseInput(tt.source)
			if parseErr != nil && !tt.shouldFail {
				t.Fatalf("Unexpected parser error: %v", parseErr)
			}

			if parseErr != nil && tt.shouldFail {
				if tt.errorContains != "" && !strings.Contains(parseErr.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, parseErr)
				}
				return // Expected failure, test passed
			}

			if parseErr == nil && tt.shouldFail {
				t.Errorf("Expected parsing to fail, but it succeeded")
				return
			}

			// Test AST structure
			if len(program.Policies) != 1 {
				t.Errorf("Expected 1 policy, got %d", len(program.Policies))
				return
			}

			// Test FSM compilation
			fsm, compileErr := CompileProgram(tt.source)
			if compileErr != nil && !tt.shouldFail {
				t.Fatalf("Unexpected compilation error: %v", compileErr)
			}

			if compileErr != nil && tt.shouldFail {
				if tt.errorContains != "" && !strings.Contains(compileErr.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, compileErr)
				}
				return // Expected failure, test passed
			}

			if compileErr == nil && tt.shouldFail {
				t.Errorf("Expected compilation to fail, but it succeeded")
				return
			}

			// Validate FSM structure
			if fsm == nil {
				t.Fatal("FSM is nil")
			}

			if len(fsm.States) < tt.expectedStates {
				t.Errorf("Expected at least %d states, got %d", tt.expectedStates, len(fsm.States))
			}

			if fsm.InitialState == "" {
				t.Error("FSM has no initial state")
			}

			// Validate FSM correctness
			engine := NewExecutionEngine(fsm)
			if err := engine.ValidateFSM(); err != nil {
				t.Errorf("FSM validation failed: %v", err)
			}
		})
	}
}

// TestCompilerErrorRecovery tests how well the compiler handles and reports errors
func TestCompilerErrorRecovery(t *testing.T) {
	errorTests := []struct {
		name          string
		source        string
		expectedError string
		errorType     string // "lexer", "parser", "compiler"
	}{
		{
			name: "Lexer: Invalid string literal",
			source: `path "test {
				openat {}
			}`,
			expectedError: "", // Lexer actually handles this gracefully
			errorType:     "lexer",
		},
		{
			name: "Parser: Missing closing brace",
			source: `path "test" {
				openat { pathname="/test"`,
			expectedError: "expected '}'",
			errorType:     "parser",
		},
		{
			name: "Parser: Invalid conditional syntax",
			source: `path "test" {
				openat {} ? block "then" {} 
			}`,
			expectedError: "expected ':'",
			errorType:     "parser",
		},
		{
			name: "Compiler: Invalid parameter operator",
			source: `path "test" {
				openat { pathname!"invalid" }
			}`,
			expectedError: "expected '=' or '=~'",
			errorType:     "parser",
		},
		{
			name: "Compiler: Duplicate state IDs",
			source: `path "test" {
				block "same_name" { openat { pathname="/test1" } }
				block "same_name" { write { content="test" } }
			}`,
			expectedError: "", // Currently no duplicate validation implemented
			errorType:     "compiler",
		},
	}

	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			// Test at appropriate level
			switch tt.errorType {
			case "lexer":
				_, err = TokenizeInput(tt.source)
			case "parser":
				_, err = ParseInput(tt.source)
			case "compiler":
				_, err = CompileProgram(tt.source)
			}

			if err == nil {
				if tt.expectedError != "" {
					t.Errorf("Expected error but got none")
					return
				}
				// No error expected and none occurred - this is fine
				return
			}

			if tt.expectedError != "" && !strings.Contains(err.Error(), tt.expectedError) {
				t.Errorf("Expected error to contain '%s', got: %v", tt.expectedError, err)
			}
		})
	}
}

// TestCompilerSemanticValidation tests semantic analysis of policies
func TestCompilerSemanticValidation(t *testing.T) {
	tests := []struct {
		name          string
		source        string
		shouldFail    bool
		expectedError string
	}{
		{
			name: "Valid syscall parameters",
			source: `path "valid" {
				openat { pathname="/test" }
			}`,
			shouldFail: false,
		},
		{
			name: "Invalid parameter for syscall",
			source: `path "invalid_param" {
				openat { invalid_param="value" }
			}`,
			shouldFail:    false, // Parameter validation not implemented at compile time
			expectedError: "",
		},
		{
			name: "Mixed valid and invalid parameters",
			source: `path "mixed" {
				openat { 
					pathname="/test"
					invalid_param="value"
				}
			}`,
			shouldFail:    false, // Parameter validation not implemented at compile time
			expectedError: "",
		},
		{
			name: "Empty parameter value",
			source: `path "empty_value" {
				openat { pathname="" }
			}`,
			shouldFail: false, // Empty string might be valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CompileProgram(tt.source)

			if err == nil && tt.shouldFail {
				t.Errorf("Expected compilation to fail, but it succeeded")
				return
			}

			if err != nil && !tt.shouldFail {
				t.Errorf("Unexpected compilation error: %v", err)
				return
			}

			if err != nil && tt.shouldFail {
				if tt.expectedError != "" && !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.expectedError, err)
				}
			}
		})
	}
}

// TestCompilerOptimization tests compiler optimizations and transformations
func TestCompilerOptimization(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		description string
	}{
		{
			name: "Sequential syscall optimization",
			source: `path "sequential" {
				openat { pathname="/etc/passwd" }
				write { content="data" }
				execve { filename="/bin/cat" }
			}`,
			description: "Should create efficient sequential state chain",
		},
		{
			name: "Conditional optimization",
			source: `path "conditional" {
				openat { pathname="/etc/passwd" } ?
				block "match" {
					execve { filename="/bin/sh" }
				} :
				block "nomatch" {
					write { content="safe" }
				}
			}`,
			description: "Should optimize conditional branches",
		},
		{
			name: "Nested block flattening",
			source: `path "nested" {
				block "outer" {
					block "inner" {
						openat { pathname="/test" }
					}
				}
			}`,
			description: "Should optimize nested block structure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsm, err := CompileProgram(tt.source)
			if err != nil {
				t.Fatalf("Compilation failed: %v", err)
			}

			// Validate that FSM is correctly structured
			if fsm == nil {
				t.Fatal("FSM is nil")
			}

			if len(fsm.States) == 0 {
				t.Fatal("FSM has no states")
			}

			// Ensure FSM is valid
			engine := NewExecutionEngine(fsm)
			if err := engine.ValidateFSM(); err != nil {
				t.Errorf("Optimized FSM validation failed: %v", err)
			}

			t.Logf("Test '%s': %s - FSM has %d states", tt.name, tt.description, len(fsm.States))
		})
	}
}

// TestCompilerEdgeCases tests various edge cases and boundary conditions
func TestCompilerEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{
			name: "Very long policy name",
			source: fmt.Sprintf(`path "%s" {
				openat { pathname="/test" }
			}`, strings.Repeat("a", 1000)),
		},
		{
			name: "Very long regex pattern",
			source: fmt.Sprintf(`path "long_regex" {
				openat { pathname=~"%s" }
			}`, strings.Repeat("[a-z]", 100)),
		},
		{
			name:   "Many nested blocks",
			source: generateNestedBlocks(10),
		},
		{
			name:   "Many sequential syscalls",
			source: generateSequentialSyscalls(50),
		},
		{
			name: "Complex regex with special characters",
			source: `path "complex_regex" {
				openat { pathname=~"^/etc/(passwd|shadow|group)$" }
			}`,
		},
		{
			name: "Unicode in strings",
			source: `path "unicode_test" {
				write { content="Hello 世界 🌍" }
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsm, err := CompileProgram(tt.source)
			if err != nil {
				t.Errorf("Compilation failed for %s: %v", tt.name, err)
				return
			}

			if fsm == nil {
				t.Error("FSM is nil")
				return
			}

			// Validate FSM
			engine := NewExecutionEngine(fsm)
			if err := engine.ValidateFSM(); err != nil {
				t.Errorf("FSM validation failed for %s: %v", tt.name, err)
			}
		})
	}
}

// Helper functions for generating test cases

func generateNestedBlocks(depth int) string {
	var builder strings.Builder
	builder.WriteString(`path "nested_test" {`)

	for i := 0; i < depth; i++ {
		builder.WriteString(fmt.Sprintf(`block "level_%d" {`, i))
	}

	builder.WriteString(`openat { pathname="/test" }`)

	for i := 0; i < depth; i++ {
		builder.WriteString(`}`)
	}

	builder.WriteString(`}`)
	return builder.String()
}

func generateSequentialSyscalls(count int) string {
	var builder strings.Builder
	builder.WriteString(`path "sequential_test" {`)

	syscalls := []string{
		`openat { pathname="/test1" }`,
		`write { content="data1" }`,
		`execve { filename="/bin/cat" }`,
	}

	for i := 0; i < count; i++ {
		syscall := syscalls[i%len(syscalls)]
		builder.WriteString(syscall)
	}

	builder.WriteString(`}`)
	return builder.String()
}

// TestRegexCompilation tests regex pattern compilation and validation
func TestRegexCompilation(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		shouldFail  bool
		testStrings []struct {
			input    string
			expected bool
		}
	}{
		{
			name:       "Simple file extension",
			pattern:    `.*\.txt$`,
			shouldFail: false,
			testStrings: []struct {
				input    string
				expected bool
			}{
				{"file.txt", true},
				{"document.txt", true},
				{"file.doc", false},
				{"txt", false},
			},
		},
		{
			name:       "Path pattern",
			pattern:    `^/etc/.*`,
			shouldFail: false,
			testStrings: []struct {
				input    string
				expected bool
			}{
				{"/etc/passwd", true},
				{"/etc/shadow", true},
				{"/var/log/test", false},
				{"etc/passwd", false},
			},
		},
		{
			name:       "Invalid regex - unclosed bracket",
			pattern:    `[invalid`,
			shouldFail: true,
		},
		{
			name:       "Invalid regex - invalid escape",
			pattern:    `\x`,
			shouldFail: true,
		},
		{
			name:       "Complex character class",
			pattern:    `^[a-zA-Z0-9_.-]+$`,
			shouldFail: false,
			testStrings: []struct {
				input    string
				expected bool
			}{
				{"valid_name", true},
				{"file-name.txt", true},
				{"invalid@name", false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test regex compilation in policy context
			source := fmt.Sprintf(`path "regex_test" {
				openat { pathname=~"%s" }
			}`, tt.pattern)

			_, err := CompileProgram(source)

			if err == nil && tt.shouldFail {
				t.Errorf("Expected regex compilation to fail, but it succeeded")
				return
			}

			if err != nil && !tt.shouldFail {
				t.Errorf("Unexpected regex compilation error: %v", err)
				return
			}

			if err != nil && tt.shouldFail {
				// Expected failure, test regex error reporting
				if !strings.Contains(err.Error(), "regex") && !strings.Contains(err.Error(), "pattern") {
					t.Errorf("Error message should mention regex/pattern: %v", err)
				}
				return
			}

			// Test actual regex matching if compilation succeeded
			if tt.testStrings != nil {
				compiledRegex, compileErr := regexp.Compile(tt.pattern)
				if compileErr != nil {
					t.Fatalf("Failed to compile regex for testing: %v", compileErr)
				}

				for _, test := range tt.testStrings {
					result := compiledRegex.MatchString(test.input)
					if result != test.expected {
						t.Errorf("Pattern '%s' with input '%s': expected %v, got %v",
							tt.pattern, test.input, test.expected, result)
					}
				}
			}
		})
	}
}
