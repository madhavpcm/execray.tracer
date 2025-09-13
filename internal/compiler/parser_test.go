package compiler

import (
	"strings"
	"testing"
)

func TestParser_BasicPolicy(t *testing.T) {
	input := `path "test_policy" {
		openat { pathname="/dev/test.txt" }
	}`

	program, err := ParseInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(program.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(program.Policies))
	}

	policy := program.Policies[0]
	if policy.Name != "test_policy" {
		t.Errorf("expected policy name 'test_policy', got '%s'", policy.Name)
	}

	if len(policy.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(policy.Statements))
	}

	syscall, ok := policy.Statements[0].(*SyscallStatement)
	if !ok {
		t.Fatalf("expected SyscallStatement, got %T", policy.Statements[0])
	}

	if syscall.Name != "openat" {
		t.Errorf("expected syscall name 'openat', got '%s'", syscall.Name)
	}

	if len(syscall.Parameters) != 1 {
		t.Fatalf("expected 1 parameter, got %d", len(syscall.Parameters))
	}

	param := syscall.Parameters[0]
	if param.Name != "pathname" {
		t.Errorf("expected parameter name 'pathname', got '%s'", param.Name)
	}

	if param.Operator != AssignOp {
		t.Errorf("expected AssignOp, got %v", param.Operator)
	}

	stringVal, ok := param.Value.(*StringValue)
	if !ok {
		t.Fatalf("expected StringValue, got %T", param.Value)
	}

	if stringVal.Value != "/dev/test.txt" {
		t.Errorf("expected value '/dev/test.txt', got '%s'", stringVal.Value)
	}
}

func TestParser_RegexParameter(t *testing.T) {
	input := `path "regex_test" {
		openat { pathname=~"/dev.*" }
	}`

	program, err := ParseInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	policy := program.Policies[0]
	syscall := policy.Statements[0].(*SyscallStatement)
	param := syscall.Parameters[0]

	if param.Operator != RegexMatchOp {
		t.Errorf("expected RegexMatchOp, got %v", param.Operator)
	}

	regexVal, ok := param.Value.(*RegexValue)
	if !ok {
		t.Fatalf("expected RegexValue, got %T", param.Value)
	}

	if regexVal.Pattern != "/dev.*" {
		t.Errorf("expected pattern '/dev.*', got '%s'", regexVal.Pattern)
	}
}

func TestParser_BlockStatement(t *testing.T) {
	input := `path "block_test" {
		block "test_block" {
			execve { pathname="sudo" }
			write {}
		}
	}`

	program, err := ParseInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	policy := program.Policies[0]
	if len(policy.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(policy.Statements))
	}

	block, ok := policy.Statements[0].(*BlockStatement)
	if !ok {
		t.Fatalf("expected BlockStatement, got %T", policy.Statements[0])
	}

	if block.Name != "test_block" {
		t.Errorf("expected block name 'test_block', got '%s'", block.Name)
	}

	if len(block.Statements) != 2 {
		t.Fatalf("expected 2 statements in block, got %d", len(block.Statements))
	}

	// Check execve statement
	execve, ok := block.Statements[0].(*SyscallStatement)
	if !ok {
		t.Fatalf("expected SyscallStatement, got %T", block.Statements[0])
	}

	if execve.Name != "execve" {
		t.Errorf("expected syscall name 'execve', got '%s'", execve.Name)
	}

	// Check write statement
	write, ok := block.Statements[1].(*SyscallStatement)
	if !ok {
		t.Fatalf("expected SyscallStatement, got %T", block.Statements[1])
	}

	if write.Name != "write" {
		t.Errorf("expected syscall name 'write', got '%s'", write.Name)
	}

	if len(write.Parameters) != 0 {
		t.Errorf("expected 0 parameters for write, got %d", len(write.Parameters))
	}
}

func TestParser_ConditionalStatement(t *testing.T) {
	input := `path "conditional_test" {
		openat { pathname=~"syscall" } ?
		block "ifcase" {
			execve { pathname=~"sudo" }
		} :
		block "elsecase" {
			write {}
		}
	}`

	program, err := ParseInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	policy := program.Policies[0]
	if len(policy.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(policy.Statements))
	}

	conditional, ok := policy.Statements[0].(*ConditionalStatement)
	if !ok {
		t.Fatalf("expected ConditionalStatement, got %T", policy.Statements[0])
	}

	// Check condition
	condition, ok := conditional.Condition.(*SyscallStatement)
	if !ok {
		t.Fatalf("expected SyscallStatement as condition, got %T", conditional.Condition)
	}

	if condition.Name != "openat" {
		t.Errorf("expected condition syscall 'openat', got '%s'", condition.Name)
	}

	// Check then block
	thenBlock, ok := conditional.ThenBlock.(*BlockStatement)
	if !ok {
		t.Fatalf("expected BlockStatement as then block, got %T", conditional.ThenBlock)
	}

	if thenBlock.Name != "ifcase" {
		t.Errorf("expected then block name 'ifcase', got '%s'", thenBlock.Name)
	}

	// Check else block
	elseBlock, ok := conditional.ElseBlock.(*BlockStatement)
	if !ok {
		t.Fatalf("expected BlockStatement as else block, got %T", conditional.ElseBlock)
	}

	if elseBlock.Name != "elsecase" {
		t.Errorf("expected else block name 'elsecase', got '%s'", elseBlock.Name)
	}
}

func TestParser_EllipsisStatement(t *testing.T) {
	input := `path "ellipsis_test" {
		write {}..
		...
	}`

	program, err := ParseInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	policy := program.Policies[0]
	if len(policy.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(policy.Statements))
	}

	// Check syscall with repetition
	syscall, ok := policy.Statements[0].(*SyscallStatement)
	if !ok {
		t.Fatalf("expected SyscallStatement, got %T", policy.Statements[0])
	}

	if syscall.Name != "write" {
		t.Errorf("expected syscall name 'write', got '%s'", syscall.Name)
	}

	if syscall.Repetition == nil {
		t.Fatal("expected repetition modifier")
	}

	if syscall.Repetition.RepType != RepetitionTwo {
		t.Errorf("expected RepetitionTwo, got %v", syscall.Repetition.RepType)
	}

	// Check standalone ellipsis
	ellipsis, ok := policy.Statements[1].(*EllipsisStatement)
	if !ok {
		t.Fatalf("expected EllipsisStatement, got %T", policy.Statements[1])
	}

	if ellipsis.EllipsisType != EllipsisThree {
		t.Errorf("expected EllipsisThree, got %v", ellipsis.EllipsisType)
	}
}

func TestParser_CompleteLanguageSpec(t *testing.T) {
	input := `path "key_logger" {
		block "openat_example" {
			openat { pathname="/dev/test.txt" }
			openat { pathname=~"/dev.*" }
		}
		
		openat { pathname=~"syscall" } ?
		block "ifcase" {
			execve { pathname=~"sudo" }
			write {}..
			...
		} :
		block "elsecase" {
			...
		}
	}`

	program, err := ParseInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(program.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(program.Policies))
	}

	policy := program.Policies[0]
	if policy.Name != "key_logger" {
		t.Errorf("expected policy name 'key_logger', got '%s'", policy.Name)
	}

	if len(policy.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(policy.Statements))
	}

	// Verify the structure matches the language spec
	block, ok := policy.Statements[0].(*BlockStatement)
	if !ok {
		t.Fatalf("expected first statement to be BlockStatement, got %T", policy.Statements[0])
	}

	if block.Name != "openat_example" {
		t.Errorf("expected block name 'openat_example', got '%s'", block.Name)
	}

	conditional, ok := policy.Statements[1].(*ConditionalStatement)
	if !ok {
		t.Fatalf("expected second statement to be ConditionalStatement, got %T", policy.Statements[1])
	}

	// Verify condition is openat syscall
	condition, ok := conditional.Condition.(*SyscallStatement)
	if !ok {
		t.Fatalf("expected condition to be SyscallStatement, got %T", conditional.Condition)
	}

	if condition.Name != "openat" {
		t.Errorf("expected condition syscall 'openat', got '%s'", condition.Name)
	}
}

func TestParser_MultiplePolicies(t *testing.T) {
	input := `path "policy1" {
		openat { pathname="/test1" }
	}
	
	path "policy2" {
		execve { pathname="/test2" }
	}`

	program, err := ParseInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(program.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(program.Policies))
	}

	if program.Policies[0].Name != "policy1" {
		t.Errorf("expected first policy name 'policy1', got '%s'", program.Policies[0].Name)
	}

	if program.Policies[1].Name != "policy2" {
		t.Errorf("expected second policy name 'policy2', got '%s'", program.Policies[1].Name)
	}
}

func TestParser_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "missing policy name",
			input:       `path { openat {} }`,
			expectError: true,
		},
		{
			name:        "missing opening brace",
			input:       `path "test" openat {} }`,
			expectError: true,
		},
		{
			name:        "missing closing brace",
			input:       `path "test" { openat {}`,
			expectError: true,
		},
		{
			name:        "invalid parameter operator",
			input:       `path "test" { openat { pathname=="test" } }`,
			expectError: true,
		},
		{
			name:        "missing parameter value",
			input:       `path "test" { openat { pathname= } }`,
			expectError: true,
		},
		{
			name:        "missing question mark in conditional",
			input:       `path "test" { openat {} block "then" {} : block "else" {} }`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseInput(tt.input)
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestParser_ASTStringRepresentation(t *testing.T) {
	input := `path "test" {
		openat { pathname="/dev/test" }
	}`

	program, err := ParseInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	str := program.String()
	if !strings.Contains(str, "path \"test\"") {
		t.Error("AST string representation should contain the policy declaration")
	}

	if !strings.Contains(str, "openat") {
		t.Error("AST string representation should contain the syscall")
	}

	if !strings.Contains(str, "pathname=\"/dev/test\"") {
		t.Error("AST string representation should contain the parameter")
	}
}

func TestParser_Position(t *testing.T) {
	input := `path "test" {
		openat { pathname="/dev/test" }
	}`

	program, err := ParseInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that positions are tracked
	policy := program.Policies[0]
	if policy.Position().Line == 0 {
		t.Error("expected position to be tracked for policy")
	}

	syscall := policy.Statements[0].(*SyscallStatement)
	if syscall.Position().Line == 0 {
		t.Error("expected position to be tracked for syscall")
	}
}
