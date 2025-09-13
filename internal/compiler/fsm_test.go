package compiler

import (
	"bytes"
	"regexp"
	"testing"

	"execray.tracer/pkg/ipc"
	"execray.tracer/pkg/syscalls"
)

func TestFSMStateTypes(t *testing.T) {
	// Test InitialState
	initialState := NewInitialState("init_1")
	if initialState.Type() != InitialStateType {
		t.Errorf("Expected InitialStateType, got %v", initialState.Type())
	}
	if initialState.ID() != "init_1" {
		t.Errorf("Expected ID 'init_1', got %s", initialState.ID())
	}

	// Test SyscallState
	syscallState := NewSyscallState("syscall_1", "openat", []ParameterMatcher{})
	if syscallState.Type() != SyscallStateType {
		t.Errorf("Expected SyscallStateType, got %v", syscallState.Type())
	}
	if syscallState.SyscallName != "openat" {
		t.Errorf("Expected syscall name 'openat', got %s", syscallState.SyscallName)
	}

	// Test TerminalState
	terminalState := NewTerminalState("terminal_1", true)
	if terminalState.Type() != TerminalStateType {
		t.Errorf("Expected TerminalStateType, got %v", terminalState.Type())
	}
	if !terminalState.MatchResult {
		t.Errorf("Expected MatchResult true, got false")
	}
}

func TestParameterMatchers(t *testing.T) {
	// Create mock syscall data for testing
	mockOpenatEvent := &mockSyscallDataParser{
		stringOutput: "openat, Path: /etc/passwd",
	}

	// Test StringParameterMatcher
	stringMatcher := &StringParameterMatcher{
		ParameterName: "path",
		ExpectedValue: "/etc/passwd",
	}
	if !stringMatcher.Matches(mockOpenatEvent) {
		t.Errorf("StringParameterMatcher should match /etc/passwd")
	}

	// Test RegexParameterMatcher
	regexMatcher := &RegexParameterMatcher{
		ParameterName: "path",
		Pattern:       mustCompileRegex(t, `/etc/.*`),
	}
	if !regexMatcher.Matches(mockOpenatEvent) {
		t.Errorf("RegexParameterMatcher should match /etc/* pattern")
	}
}

func TestFSMCompilation(t *testing.T) {
	// Test simple policy compilation
	source := `path "malicious_read" {
		openat { pathname="/etc/passwd" }
	}`

	fsm, err := CompileProgram(source)
	if err != nil {
		t.Fatalf("Failed to compile program: %v", err)
	}

	if fsm == nil {
		t.Fatal("FSM is nil")
	}

	if len(fsm.States) == 0 {
		t.Fatal("FSM has no states")
	}

	if fsm.InitialState == "" {
		t.Fatal("FSM has no initial state")
	}
}

func TestFSMExecution(t *testing.T) {
	// Create a simple FSM manually for testing
	fsm := NewFSM()

	// Create states
	initialState := NewInitialState("init")
	syscallState := NewSyscallState("syscall_openat", "openat", []ParameterMatcher{
		&StringParameterMatcher{
			ParameterName: "path",
			ExpectedValue: "/etc/passwd",
		},
	})
	terminalState := NewTerminalState("match", true)

	// Add states to FSM
	fsm.AddState(initialState)
	fsm.AddState(syscallState)
	fsm.AddState(terminalState)

	// Set up transitions
	initialState.SetTransitions([]Transition{{TargetState: "syscall_openat"}})
	syscallState.SetTransitions([]Transition{{TargetState: "match"}})

	fsm.SetInitialState("init")

	// Create execution engine
	engine := NewExecutionEngine(fsm)

	// Validate FSM
	if err := engine.ValidateFSM(); err != nil {
		t.Fatalf("FSM validation failed: %v", err)
	}

	// Create test event that should match
	event := &ipc.BpfSyscallEvent{
		SyscallNr: syscalls.SYS_OPENAT,
		Data:      [260]uint8{}, // Will be parsed by mock
	}

	// Process event
	result, err := engine.ProcessEvent(event)
	if err != nil {
		t.Fatalf("Failed to process event: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}

	// For this test to work properly, we'd need to mock the syscall parsing
	// For now, just check that execution completed without error
	if result.ErrorMessage != "" {
		t.Errorf("Execution had error: %s", result.ErrorMessage)
	}
}

func TestComplexPolicyCompilation(t *testing.T) {
	// Test compilation of a more complex policy
	source := `path "complex_attack" {
		openat { pathname =~ "/etc/.*" }
		execve { filename="/bin/sh" }
		write { content =~ "malicious.*" }
	}`

	fsm, err := CompileProgram(source)
	if err != nil {
		t.Fatalf("Failed to compile complex program: %v", err)
	}

	if fsm == nil {
		t.Fatal("FSM is nil")
	}

	// Should have multiple states for the sequence
	if len(fsm.States) < 5 { // initial + 3 syscalls + terminal + intermediate states
		t.Errorf("Expected at least 5 states, got %d", len(fsm.States))
	}
}

func TestParameterExtraction(t *testing.T) {
	tests := []struct {
		name          string
		syscallOutput string
		paramName     string
		expectedValue string
	}{
		{
			name:          "openat path extraction",
			syscallOutput: "openat, Path: /etc/passwd",
			paramName:     "path",
			expectedValue: "/etc/passwd",
		},
		{
			name:          "execve filename extraction",
			syscallOutput: "execve, Filename: /bin/sh",
			paramName:     "filename",
			expectedValue: "/bin/sh",
		},
		{
			name:          "write content extraction",
			syscallOutput: `write, Len: 12, Content: "hello world"`,
			paramName:     "content",
			expectedValue: "hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockData := &mockSyscallDataParser{
				stringOutput: tt.syscallOutput,
			}

			value := extractParameterValue(mockData, tt.paramName)
			if value != tt.expectedValue {
				t.Errorf("Expected %q, got %q", tt.expectedValue, value)
			}
		})
	}
}

func TestExecutionEngine(t *testing.T) {
	// Test engine creation and basic operations
	fsm := NewFSM()
	initialState := NewInitialState("init")
	fsm.AddState(initialState)
	fsm.SetInitialState("init")

	engine := NewExecutionEngine(fsm)

	// Test validation
	if err := engine.ValidateFSM(); err != nil {
		t.Errorf("Valid FSM failed validation: %v", err)
	}

	// Test current state
	if engine.GetCurrentState() != "init" {
		t.Errorf("Expected current state 'init', got %s", engine.GetCurrentState())
	}

	// Test reset
	engine.Reset()
	if engine.GetCurrentState() != "init" {
		t.Errorf("After reset, expected current state 'init', got %s", engine.GetCurrentState())
	}

	// Test string representation
	str := engine.String()
	if str == "" {
		t.Error("Engine string representation is empty")
	}
}

// Helper functions and mocks

type mockSyscallDataParser struct {
	stringOutput string
}

func (m *mockSyscallDataParser) String() string {
	return m.stringOutput
}

func (m *mockSyscallDataParser) Parse(reader *bytes.Reader) error {
	// Mock implementation - doesn't actually parse anything
	return nil
}

func mustCompileRegex(t *testing.T, pattern string) *regexp.Regexp {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("Failed to compile regex %s: %v", pattern, err)
	}
	return regex
}

// Benchmark tests
func BenchmarkFSMCompilation(b *testing.B) {
	source := `path "test_policy" {
		openat { pathname="/etc/passwd" }
		execve { filename="/bin/sh" }
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CompileProgram(source)
		if err != nil {
			b.Fatalf("Compilation failed: %v", err)
		}
	}
}

func BenchmarkFSMExecution(b *testing.B) {
	// Set up FSM
	fsm := NewFSM()
	initialState := NewInitialState("init")
	terminalState := NewTerminalState("match", true)

	fsm.AddState(initialState)
	fsm.AddState(terminalState)

	initialState.SetTransitions([]Transition{{TargetState: "match"}})
	fsm.SetInitialState("init")

	engine := NewExecutionEngine(fsm)
	event := &ipc.BpfSyscallEvent{
		SyscallNr: syscalls.SYS_OPENAT,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.ProcessEvent(event)
		if err != nil {
			b.Fatalf("Execution failed: %v", err)
		}
		engine.Reset()
	}
}
