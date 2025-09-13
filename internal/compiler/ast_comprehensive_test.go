package compiler

import (
	"reflect"
	"strings"
	"testing"
)

// TestASTNodeTypes tests creation and validation of all AST node types
func TestASTNodeTypes(t *testing.T) {
	tests := []struct {
		name      string
		source    string
		validator func(*testing.T, *Program)
	}{
		{
			name: "Policy node structure",
			source: `path "test_policy" {
				openat { pathname="/test" }
			}`,
			validator: func(t *testing.T, program *Program) {
				if len(program.Policies) != 1 {
					t.Errorf("Expected 1 policy, got %d", len(program.Policies))
					return
				}
				policy := program.Policies[0]
				if policy.Name != "test_policy" {
					t.Errorf("Expected policy name 'test_policy', got '%s'", policy.Name)
				}
				if len(policy.Statements) != 1 {
					t.Errorf("Expected 1 statement, got %d", len(policy.Statements))
				}
			},
		},
		{
			name: "SyscallStatement node",
			source: `path "syscall_test" {
				openat { 
					pathname="/etc/passwd"
					flags="O_RDONLY"
				}
			}`,
			validator: func(t *testing.T, program *Program) {
				stmt := program.Policies[0].Statements[0]
				syscall, ok := stmt.(*SyscallStatement)
				if !ok {
					t.Errorf("Expected SyscallStatement, got %T", stmt)
					return
				}
				if syscall.Name != "openat" {
					t.Errorf("Expected syscall name 'openat', got '%s'", syscall.Name)
				}
				if len(syscall.Parameters) != 2 {
					t.Errorf("Expected 2 parameters, got %d", len(syscall.Parameters))
				}
				// Check parameter types
				pathParam := syscall.Parameters[0]
				if pathParam.Name != "pathname" {
					t.Errorf("Expected parameter name 'pathname', got '%s'", pathParam.Name)
				}
				if _, ok := pathParam.Value.(*StringValue); !ok {
					t.Errorf("Expected StringValue for pathname, got %T", pathParam.Value)
				}
			},
		},
		{
			name: "BlockStatement node",
			source: `path "block_test" {
				block "test_block" {
					openat { pathname="/test" }
					write {}
				}
			}`,
			validator: func(t *testing.T, program *Program) {
				stmt := program.Policies[0].Statements[0]
				block, ok := stmt.(*BlockStatement)
				if !ok {
					t.Errorf("Expected BlockStatement, got %T", stmt)
					return
				}
				if block.Name != "test_block" {
					t.Errorf("Expected block name 'test_block', got '%s'", block.Name)
				}
				if len(block.Statements) != 2 {
					t.Errorf("Expected 2 statements in block, got %d", len(block.Statements))
				}
			},
		},
		{
			name: "ConditionalStatement node",
			source: `path "conditional_test" {
				openat { pathname="/test" } ?
				block "then_block" {
					execve { filename="/bin/sh" }
				} :
				block "else_block" {
					write {}
				}
			}`,
			validator: func(t *testing.T, program *Program) {
				stmt := program.Policies[0].Statements[0]
				conditional, ok := stmt.(*ConditionalStatement)
				if !ok {
					t.Errorf("Expected ConditionalStatement, got %T", stmt)
					return
				}

				// Check condition
				if _, ok := conditional.Condition.(*SyscallStatement); !ok {
					t.Errorf("Expected SyscallStatement as condition, got %T", conditional.Condition)
				}

				// Check then block
				thenBlock, ok := conditional.ThenBlock.(*BlockStatement)
				if !ok {
					t.Errorf("Expected BlockStatement as then block, got %T", conditional.ThenBlock)
				} else if thenBlock.Name != "then_block" {
					t.Errorf("Expected then block name 'then_block', got '%s'", thenBlock.Name)
				}

				// Check else block
				elseBlock, ok := conditional.ElseBlock.(*BlockStatement)
				if !ok {
					t.Errorf("Expected BlockStatement as else block, got %T", conditional.ElseBlock)
				} else if elseBlock.Name != "else_block" {
					t.Errorf("Expected else block name 'else_block', got '%s'", elseBlock.Name)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := ParseInput(tt.source)
			if err != nil {
				t.Fatalf("Parsing failed: %v", err)
			}
			tt.validator(t, program)
		})
	}
}

// TestASTValueTypes tests all value type nodes in AST
func TestASTValueTypes(t *testing.T) {
	tests := []struct {
		name       string
		source     string
		paramName  string
		valueCheck func(*testing.T, ParameterValue)
	}{
		{
			name: "StringValue",
			source: `path "string_test" {
				openat { pathname="/etc/passwd" }
			}`,
			paramName: "pathname",
			valueCheck: func(t *testing.T, v ParameterValue) {
				stringVal, ok := v.(*StringValue)
				if !ok {
					t.Errorf("Expected StringValue, got %T", v)
					return
				}
				if stringVal.Value != "/etc/passwd" {
					t.Errorf("Expected '/etc/passwd', got '%s'", stringVal.Value)
				}
			},
		},
		{
			name: "RegexValue",
			source: `path "regex_test" {
				openat { pathname=~"/etc/.*" }
			}`,
			paramName: "pathname",
			valueCheck: func(t *testing.T, v ParameterValue) {
				regexVal, ok := v.(*RegexValue)
				if !ok {
					t.Errorf("Expected RegexValue, got %T", v)
					return
				}
				if regexVal.Pattern != "/etc/.*" {
					t.Errorf("Expected '/etc/.*', got '%s'", regexVal.Pattern)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := ParseInput(tt.source)
			if err != nil {
				t.Fatalf("Parsing failed: %v", err)
			}

			syscall := program.Policies[0].Statements[0].(*SyscallStatement)
			var param *Parameter
			for i, p := range syscall.Parameters {
				if p.Name == tt.paramName {
					param = &syscall.Parameters[i]
					break
				}
			}

			if param == nil {
				t.Fatalf("Parameter '%s' not found", tt.paramName)
			}

			tt.valueCheck(t, param.Value)
		})
	}
}

// TestASTParameterOperators tests all parameter operator types
func TestASTParameterOperators(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected ParameterOperator
	}{
		{
			name: "AssignOp",
			source: `path "assign_test" {
				openat { pathname="/test" }
			}`,
			expected: AssignOp,
		},
		{
			name: "RegexMatchOp",
			source: `path "regex_test" {
				openat { pathname=~"/test.*" }
			}`,
			expected: RegexMatchOp,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := ParseInput(tt.source)
			if err != nil {
				t.Fatalf("Parsing failed: %v", err)
			}

			syscall := program.Policies[0].Statements[0].(*SyscallStatement)
			if len(syscall.Parameters) == 0 {
				t.Fatal("No parameters found")
			}

			param := syscall.Parameters[0]
			if param.Operator != tt.expected {
				t.Errorf("Expected operator %v, got %v", tt.expected, param.Operator)
			}
		})
	}
}

// TestComplexASTStructures tests complex nested AST structures
func TestComplexASTStructures(t *testing.T) {
	tests := []struct {
		name      string
		source    string
		validator func(*testing.T, *Program)
	}{
		{
			name: "Deeply nested blocks",
			source: `path "deep_nesting" {
				block "level1" {
					block "level2" {
						block "level3" {
							openat { pathname="/test" }
						}
					}
				}
			}`,
			validator: func(t *testing.T, program *Program) {
				// Navigate to deepest level
				stmt := program.Policies[0].Statements[0]
				level1, ok := stmt.(*BlockStatement)
				if !ok || level1.Name != "level1" {
					t.Errorf("Expected level1 BlockStatement")
					return
				}

				level2, ok := level1.Statements[0].(*BlockStatement)
				if !ok || level2.Name != "level2" {
					t.Errorf("Expected level2 BlockStatement")
					return
				}

				level3, ok := level2.Statements[0].(*BlockStatement)
				if !ok || level3.Name != "level3" {
					t.Errorf("Expected level3 BlockStatement")
					return
				}

				syscall, ok := level3.Statements[0].(*SyscallStatement)
				if !ok || syscall.Name != "openat" {
					t.Errorf("Expected openat SyscallStatement at deepest level")
				}
			},
		},
		{
			name: "Complex conditional with nested blocks",
			source: `path "complex_conditional" {
				openat { pathname=~"/etc/.*" } ?
				block "secure_access" {
					execve { filename="/bin/sh" } ?
					block "shell_exec" {
						write { content="executed" }
					} :
					block "no_shell" {
						write { content="blocked" }
					}
				} :
				block "normal_access" {
					write { content="normal" }
				}
			}`,
			validator: func(t *testing.T, program *Program) {
				stmt := program.Policies[0].Statements[0]
				conditional, ok := stmt.(*ConditionalStatement)
				if !ok {
					t.Errorf("Expected ConditionalStatement")
					return
				}

				// Check nested conditional in then block
				thenBlock := conditional.ThenBlock.(*BlockStatement)
				nestedConditional, ok := thenBlock.Statements[0].(*ConditionalStatement)
				if !ok {
					t.Errorf("Expected nested ConditionalStatement")
					return
				}

				// Verify nested structure
				nestedThenBlock := nestedConditional.ThenBlock.(*BlockStatement)
				if nestedThenBlock.Name != "shell_exec" {
					t.Errorf("Expected nested then block name 'shell_exec'")
				}
			},
		},
		{
			name: "Multiple policies in single program",
			source: `
			path "policy1" {
				openat { pathname="/test1" }
			}
			path "policy2" {
				write { content="test2" }
			}
			path "policy3" {
				execve { filename="/bin/bash" }
			}`,
			validator: func(t *testing.T, program *Program) {
				if len(program.Policies) != 3 {
					t.Errorf("Expected 3 policies, got %d", len(program.Policies))
					return
				}

				expectedNames := []string{"policy1", "policy2", "policy3"}
				for i, policy := range program.Policies {
					if policy.Name != expectedNames[i] {
						t.Errorf("Policy %d: expected name '%s', got '%s'", i, expectedNames[i], policy.Name)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := ParseInput(tt.source)
			if err != nil {
				t.Fatalf("Parsing failed: %v", err)
			}
			tt.validator(t, program)
		})
	}
}

// TestASTStringRepresentation tests string representation of AST nodes
func TestASTStringRepresentation(t *testing.T) {
	source := `path "string_test" {
		openat { pathname="/test" }
		block "test_block" {
			write { content="hello" }
		}
	}`

	program, err := ParseInput(source)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	} // Test that string representations don't panic and contain expected content
	tests := []struct {
		name     string
		node     interface{}
		contains []string
	}{
		{
			name:     "Program string",
			node:     program,
			contains: []string{"string_test"},
		},
		{
			name:     "Policy string",
			node:     program.Policies[0],
			contains: []string{"string_test", "openat"},
		},
		{
			name:     "SyscallStatement string",
			node:     program.Policies[0].Statements[0],
			contains: []string{"openat", "pathname", "/test"},
		},
		{
			name:     "BlockStatement string",
			node:     program.Policies[0].Statements[1],
			contains: []string{"test_block", "write"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var str string

			// Handle String() method call based on type
			switch v := tt.node.(type) {
			case *Program:
				str = v.String()
			case *PolicyStatement:
				str = v.String()
			case PolicyStatement:
				str = (&v).String() // Take address for pointer receiver
			case *SyscallStatement:
				str = v.String()
			case *BlockStatement:
				str = v.String()
			default:
				// Fallback to reflection
				val := reflect.ValueOf(tt.node)
				if val.Kind() != reflect.Ptr && val.CanAddr() {
					val = val.Addr()
				}
				method := val.MethodByName("String")
				if method.IsValid() {
					result := method.Call(nil)
					if len(result) > 0 {
						str = result[0].String()
					}
				}
			}

			if str == "" {
				t.Errorf("String representation is empty")
				return
			}

			for _, expected := range tt.contains {
				if !containsIgnoreCase(str, expected) {
					t.Errorf("String representation should contain '%s', got: %s", expected, str)
				}
			}
		})
	}
}

// TestASTEquality tests equality comparison between AST nodes
func TestASTEquality(t *testing.T) {
	source1 := `path "test" {
		openat { pathname="/test" }
	}`

	source2 := `path "test" {
		openat { pathname="/test" }
	}`

	source3 := `path "different" {
		openat { pathname="/test" }
	}`

	program1, err1 := ParseInput(source1)
	program2, err2 := ParseInput(source2)
	program3, err3 := ParseInput(source3)

	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatalf("Parsing failed: %v, %v, %v", err1, err2, err3)
	}

	// Test deep equality of identical ASTs
	if !reflect.DeepEqual(program1, program2) {
		t.Error("Identical programs should be deeply equal")
	}

	// Test inequality of different ASTs
	if reflect.DeepEqual(program1, program3) {
		t.Error("Different programs should not be deeply equal")
	}

	// Test specific node equality
	policy1 := program1.Policies[0]
	policy2 := program2.Policies[0]
	policy3 := program3.Policies[0]

	if !reflect.DeepEqual(policy1, policy2) {
		t.Error("Identical policies should be deeply equal")
	}

	if reflect.DeepEqual(policy1, policy3) {
		t.Error("Different policies should not be deeply equal")
	}
}

// TestASTCloning tests cloning/copying of AST nodes
func TestASTCloning(t *testing.T) {
	source := `path "clone_test" {
		openat { pathname="/test" }
		block "test_block" {
			write { content="hello" }
		}
	}`

	original, err := ParseInput(source)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	}

	// Create a "clone" by parsing the same source again
	clone, err := ParseInput(source)
	if err != nil {
		t.Fatalf("Cloning parse failed: %v", err)
	}

	// Verify they are equal but not the same object
	if !reflect.DeepEqual(original, clone) {
		t.Error("Clone should be deeply equal to original")
	}

	// Verify they are different objects
	if original == clone {
		t.Error("Clone should be a different object than original")
	}

	// Modify clone and verify original is unchanged
	clone.Policies[0].Name = "modified_name"
	if original.Policies[0].Name == "modified_name" {
		t.Error("Modifying clone should not affect original")
	}
}

// TestASTValidation tests semantic validation of AST structures
func TestASTValidation(t *testing.T) {
	tests := []struct {
		name          string
		source        string
		shouldBeValid bool
		description   string
	}{
		{
			name: "Valid simple policy",
			source: `path "valid" {
				openat { pathname="/test" }
			}`,
			shouldBeValid: true,
			description:   "Simple valid policy should pass validation",
		},
		{
			name: "Valid complex policy",
			source: `path "complex_valid" {
				openat { pathname=~"/etc/.*" } ?
				block "secure" {
					execve { filename="/bin/sh" }
				} :
				block "normal" {
					write {}
				}
			}`,
			shouldBeValid: true,
			description:   "Complex valid policy should pass validation",
		},
		{
			name: "Empty policy",
			source: `path "empty" {
			}`,
			shouldBeValid: false,
			description:   "Empty policy should fail validation",
		},
		{
			name: "Policy with empty block",
			source: `path "empty_block" {
				block "empty" {
				}
			}`,
			shouldBeValid: false,
			description:   "Policy with empty block should fail validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := ParseInput(tt.source)
			if err != nil {
				if tt.shouldBeValid {
					t.Fatalf("Parsing failed for valid case: %v", err)
				}
				return // Expected parsing failure
			}

			// Perform basic validation
			isValid := validateASTStructure(program)
			if isValid != tt.shouldBeValid {
				t.Errorf("%s: expected validity %v, got %v", tt.description, tt.shouldBeValid, isValid)
			}
		})
	}
}

// Helper functions

func containsIgnoreCase(text, substr string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(substr))
}

func validateASTStructure(program *Program) bool {
	if len(program.Policies) == 0 {
		return false
	}

	for _, policy := range program.Policies {
		if policy.Name == "" {
			return false
		}
		if len(policy.Statements) == 0 {
			return false
		}
		if !validateStatements(policy.Statements) {
			return false
		}
	}

	return true
}

func validateStatements(statements []Statement) bool {
	for _, stmt := range statements {
		switch s := stmt.(type) {
		case *SyscallStatement:
			if s.Name == "" {
				return false
			}
		case *BlockStatement:
			if s.Name == "" {
				return false
			}
			if len(s.Statements) == 0 {
				return false
			}
			if !validateStatements(s.Statements) {
				return false
			}
		case *ConditionalStatement:
			if s.Condition == nil || s.ThenBlock == nil || s.ElseBlock == nil {
				return false
			}
		}
	}
	return true
}
