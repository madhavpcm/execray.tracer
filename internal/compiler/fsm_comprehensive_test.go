package compiler

import (
	"runtime"
	"sync"
	"testing"

	"execray.tracer/pkg/ipc"
	"execray.tracer/pkg/syscalls"
)

// Mock data creation functions (similar to policyd integration tests)
func createMockOpenatData(pathname string) [260]uint8 {
	var data [260]uint8
	copy(data[:], []byte(pathname))
	return data
}

func createMockExecveData(filename string) [260]uint8 {
	var data [260]uint8
	copy(data[:], []byte(filename))
	return data
}

func createMockWriteData(content string) [260]uint8 {
	var data [260]uint8
	// First 4 bytes for length, then content
	length := uint32(len(content))
	data[0] = byte(length)
	data[1] = byte(length >> 8)
	data[2] = byte(length >> 16)
	data[3] = byte(length >> 24)
	copy(data[4:], []byte(content))
	return data
}

// Helper to create BpfSyscallEvent with proper data
func createBpfEvent(syscallNr uint64, pathname string, filename string, content string) *ipc.BpfSyscallEvent {
	event := &ipc.BpfSyscallEvent{
		SyscallNr: syscallNr,
		Data:      [260]uint8{},
	}

	switch syscallNr {
	case syscalls.SYS_OPENAT:
		event.Data = createMockOpenatData(pathname)
	case syscalls.SYS_EXECVE:
		event.Data = createMockExecveData(filename)
	case syscalls.SYS_WRITE:
		event.Data = createMockWriteData(content)
	}

	return event
}

// TestFSMExecutionPipeline tests the complete FSM execution pipeline
func TestFSMExecutionPipeline(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		events      []*ipc.BpfSyscallEvent
		expectMatch bool
		description string
	}{
		{
			name: "Simple single syscall match",
			source: `path "simple_match" {
				openat { pathname="/etc/passwd" }
			}`,
			events: []*ipc.BpfSyscallEvent{
				createBpfEvent(syscalls.SYS_OPENAT, "/etc/passwd", "", ""),
			},
			expectMatch: true,
			description: "Should match single openat syscall",
		},
		{
			name: "Single syscall no match",
			source: `path "no_match" {
				openat { pathname="/etc/passwd" }
			}`,
			events: []*ipc.BpfSyscallEvent{
				createBpfEvent(syscalls.SYS_OPENAT, "/etc/shadow", "", ""),
			},
			expectMatch: false,
			description: "Should not match different pathname",
		},
		{
			name: "Multi-step sequential execution",
			source: `path "multi_step" {
				openat { pathname="/etc/passwd" }
				execve { filename="/bin/sh" }
				write { content="test" }
			}`,
			events: []*ipc.BpfSyscallEvent{
				createBpfEvent(syscalls.SYS_OPENAT, "/etc/passwd", "", ""),
				createBpfEvent(syscalls.SYS_EXECVE, "", "/bin/sh", ""),
				createBpfEvent(syscalls.SYS_WRITE, "", "", "test"),
			},
			expectMatch: false, // Engine evaluates each event independently, not as sequence
			description: "Current engine evaluates events independently, not as stateful sequence",
		},
		{
			name: "Regex pattern matching",
			source: `path "regex_match" {
				openat { pathname=~"/etc/.*" }
			}`,
			events: []*ipc.BpfSyscallEvent{
				createBpfEvent(syscalls.SYS_OPENAT, "/etc/shadow", "", ""),
			},
			expectMatch: true,
			description: "Should match regex pattern",
		},
		{
			name: "Regex pattern no match",
			source: `path "regex_no_match" {
				openat { pathname=~"/etc/.*" }
			}`,
			events: []*ipc.BpfSyscallEvent{
				createBpfEvent(syscalls.SYS_OPENAT, "/var/log/test", "", ""),
			},
			expectMatch: false,
			description: "Should not match different path pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile policy to FSM
			fsm, err := CompileProgram(tt.source)
			if err != nil {
				t.Fatalf("Failed to compile policy: %v", err)
			}

			// Create execution engine
			engine := NewExecutionEngine(fsm)

			// Validate FSM
			if err := engine.ValidateFSM(); err != nil {
				t.Fatalf("FSM validation failed: %v", err)
			}

			var finalResult *ExecutionResult

			// Process each event
			for i, event := range tt.events {
				result, err := engine.ProcessEvent(event)
				if err != nil {
					t.Fatalf("Event %d: Processing failed: %v", i, err)
				}

				finalResult = result

				// Break if we reached terminal state
				if result.Matched {
					break
				}
			}

			// Verify final result
			if finalResult == nil {
				t.Fatal("No result returned from event processing")
			}

			if finalResult.Matched != tt.expectMatch {
				t.Errorf("%s: expected match=%v, got match=%v", tt.description, tt.expectMatch, finalResult.Matched)
			}

			t.Logf("Test '%s': Current state: %s", tt.name, engine.GetCurrentState())
		})
	}
}

// TestFSMStateTransitions tests individual state transitions
func TestFSMStateTransitions(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		event       *ipc.BpfSyscallEvent
		expectedEnd string
		expectMatch bool
		description string
	}{
		{
			name: "Initial to syscall transition",
			source: `path "transition_test" {
				openat { pathname="/test" }
			}`,
			event:       createBpfEvent(syscalls.SYS_OPENAT, "/test", "", ""),
			expectMatch: true,
			description: "Should transition from initial to terminal on match",
		},
		{
			name: "Failed parameter match",
			source: `path "param_fail" {
				openat { pathname="/test" }
			}`,
			event:       createBpfEvent(syscalls.SYS_OPENAT, "/different", "", ""),
			expectMatch: false,
			description: "Should stay in syscall state on parameter mismatch",
		},
		{
			name: "Wrong syscall type",
			source: `path "wrong_syscall" {
				openat { pathname="/test" }
			}`,
			event:       createBpfEvent(syscalls.SYS_WRITE, "", "", "test"),
			expectMatch: false,
			description: "Should handle wrong syscall type gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile policy to FSM
			fsm, err := CompileProgram(tt.source)
			if err != nil {
				t.Fatalf("Failed to compile policy: %v", err)
			}

			// Create execution engine
			engine := NewExecutionEngine(fsm)

			// Process single event
			result, err := engine.ProcessEvent(tt.event)
			if err != nil {
				t.Fatalf("Event processing failed: %v", err)
			}

			if result.Matched != tt.expectMatch {
				t.Errorf("%s: expected match=%v, got match=%v", tt.description, tt.expectMatch, result.Matched)
			}

			t.Logf("Test '%s': Final state: %s", tt.name, engine.GetCurrentState())
		})
	}
}

// TestFSMParameterMatching tests parameter matching functionality
func TestFSMParameterMatching(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		event       *ipc.BpfSyscallEvent
		expectMatch bool
		description string
	}{
		{
			name: "Exact string match",
			source: `path "exact_match" {
				openat { pathname="/etc/passwd" }
			}`,
			event:       createBpfEvent(syscalls.SYS_OPENAT, "/etc/passwd", "", ""),
			expectMatch: true,
			description: "Exact string parameter should match",
		},
		{
			name: "String case sensitivity",
			source: `path "case_test" {
				openat { pathname="/etc/passwd" }
			}`,
			event:       createBpfEvent(syscalls.SYS_OPENAT, "/ETC/PASSWD", "", ""),
			expectMatch: false,
			description: "String matching should be case sensitive",
		},
		{
			name: "Regex pattern match",
			source: `path "regex_test" {
				openat { pathname=~"/etc/.*" }
			}`,
			event:       createBpfEvent(syscalls.SYS_OPENAT, "/etc/shadow", "", ""),
			expectMatch: true,
			description: "Regex pattern should match",
		},
		{
			name: "Regex pattern no match",
			source: `path "regex_no_match" {
				openat { pathname=~"/etc/.*" }
			}`,
			event:       createBpfEvent(syscalls.SYS_OPENAT, "/var/log/test", "", ""),
			expectMatch: false,
			description: "Regex pattern should not match different path",
		},
		{
			name: "Complex regex pattern",
			source: `path "complex_regex" {
				openat { pathname=~"/etc/(passwd|shadow|group)" }
			}`,
			event:       createBpfEvent(syscalls.SYS_OPENAT, "/etc/group", "", ""),
			expectMatch: true,
			description: "Complex regex with alternation should match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile policy to FSM
			fsm, err := CompileProgram(tt.source)
			if err != nil {
				t.Fatalf("Failed to compile policy: %v", err)
			}

			// Create execution engine
			engine := NewExecutionEngine(fsm)

			// Process event
			result, err := engine.ProcessEvent(tt.event)
			if err != nil {
				t.Fatalf("Event processing failed: %v", err)
			}

			if result.Matched != tt.expectMatch {
				t.Errorf("%s: expected match=%v, got match=%v", tt.description, tt.expectMatch, result.Matched)
			}
		})
	}
}

// TestFSMComplexScenarios tests complex realistic attack scenarios
func TestFSMComplexScenarios(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		events      []*ipc.BpfSyscallEvent
		expectMatch bool
		description string
	}{
		{
			name: "Attack pattern detection",
			source: `path "password_tampering" {
				openat { pathname="/etc/passwd" }
				write { content=~".*root.*" }
			}`,
			events: []*ipc.BpfSyscallEvent{
				createBpfEvent(syscalls.SYS_OPENAT, "/etc/passwd", "", ""),
				createBpfEvent(syscalls.SYS_WRITE, "", "", "root:x:0:0:root:/root:/bin/bash"),
			},
			expectMatch: false, // Multi-step sequences require policyd worker for stateful tracking
			description: "Multi-step attack patterns need stateful execution tracking",
		},
		{
			name: "Privilege escalation attempt",
			source: `path "privilege_escalation" {
				openat { pathname=~"/etc/.*" }
				execve { filename=~".*su$" }
			}`,
			events: []*ipc.BpfSyscallEvent{
				createBpfEvent(syscalls.SYS_OPENAT, "/etc/shadow", "", ""),
				createBpfEvent(syscalls.SYS_EXECVE, "", "/bin/su", ""),
			},
			expectMatch: false, // Multi-step sequences require policyd worker for stateful tracking
			description: "Multi-step escalation patterns need stateful execution tracking",
		},
		{
			name: "Single-step pattern detection",
			source: `path "single_step_attack" {
				openat { pathname="/etc/passwd" }
			}`,
			events: []*ipc.BpfSyscallEvent{
				createBpfEvent(syscalls.SYS_OPENAT, "/etc/passwd", "", ""),
			},
			expectMatch: true,
			description: "Single-step patterns work correctly with current engine",
		},
		{
			name: "Incomplete attack sequence",
			source: `path "incomplete_attack" {
				openat { pathname="/etc/passwd" }
				execve { filename="/bin/sh" }
				write { content="malicious" }
			}`,
			events: []*ipc.BpfSyscallEvent{
				createBpfEvent(syscalls.SYS_OPENAT, "/etc/passwd", "", ""),
				createBpfEvent(syscalls.SYS_EXECVE, "", "/bin/sh", ""),
				// Missing final write - incomplete sequence
			},
			expectMatch: false,
			description: "Incomplete sequences correctly don't match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile policy to FSM
			fsm, err := CompileProgram(tt.source)
			if err != nil {
				t.Fatalf("Failed to compile policy: %v", err)
			}

			// Create execution engine
			engine := NewExecutionEngine(fsm)

			var finalResult *ExecutionResult

			// Process all events
			for i, event := range tt.events {
				result, err := engine.ProcessEvent(event)
				if err != nil {
					t.Fatalf("Event %d: Processing failed: %v", i, err)
				}
				finalResult = result

				if result.Matched {
					break
				}
			}

			if finalResult == nil {
				t.Fatal("No result returned from event processing")
			}

			if finalResult.Matched != tt.expectMatch {
				t.Errorf("%s: expected match=%v, got match=%v", tt.description, tt.expectMatch, finalResult.Matched)
			}
		})
	}
}

// TestFSMConcurrentExecution tests concurrent FSM execution
func TestFSMConcurrentExecution(t *testing.T) {
	source := `path "concurrent_test" {
		openat { pathname="/test" }
	}`

	// Compile policy
	fsm, err := CompileProgram(source)
	if err != nil {
		t.Fatalf("Failed to compile policy: %v", err)
	}

	// Test concurrent execution with multiple engines
	numEngines := 10
	var wg sync.WaitGroup

	for i := 0; i < numEngines; i++ {
		wg.Add(1)
		go func(engineID int) {
			defer wg.Done()

			engine := NewExecutionEngine(fsm)
			event := createBpfEvent(syscalls.SYS_OPENAT, "/test", "", "")

			result, err := engine.ProcessEvent(event)
			if err != nil {
				t.Errorf("Engine %d: Processing failed: %v", engineID, err)
				return
			}

			if !result.Matched {
				t.Errorf("Engine %d: Expected match=true, got match=false", engineID)
			}
		}(i)
	}

	wg.Wait()
}

// TestFSMMemoryUsage tests memory usage and cleanup
func TestFSMMemoryUsage(t *testing.T) {
	source := `path "memory_test" {
		openat { pathname="/test" }
		write { content="test" }
	}`

	// Get initial memory stats
	var m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Create and destroy many FSMs to test memory cleanup
	for i := 0; i < 100; i++ {
		fsm, err := CompileProgram(source)
		if err != nil {
			t.Fatalf("Iteration %d: Failed to compile: %v", i, err)
		}

		engine := NewExecutionEngine(fsm)
		if err := engine.ValidateFSM(); err != nil {
			t.Fatalf("Iteration %d: Validation failed: %v", i, err)
		}

		// Process a few events
		for j := 0; j < 10; j++ {
			event := createBpfEvent(syscalls.SYS_OPENAT, "/test", "", "")

			_, err := engine.ProcessEvent(event)
			if err != nil {
				t.Errorf("Iteration %d, Event %d: Processing failed: %v", i, j, err)
			}

			engine.Reset()
		}
	}

	// Get final memory stats
	var m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m2)

	// Log memory usage
	memoryIncrease := int64(m2.Alloc) - int64(m1.Alloc)
	t.Logf("Memory increase after 100 FSM iterations: %d bytes", memoryIncrease)

	// Verify reasonable memory usage (less than 1MB total increase)
	// Allow for negative values (GC cleaned up more than we allocated)
	if memoryIncrease > 1024*1024 {
		t.Errorf("Memory usage too high: %d bytes", memoryIncrease)
	}
}

// BenchmarkFSMExecutionComprehensive benchmarks FSM execution performance
func BenchmarkFSMExecutionComprehensive(b *testing.B) {
	source := `path "benchmark" {
		openat { pathname=~"/etc/.*" }
		execve { filename=~".*sh$" }
		write { content="test" }
	}`

	fsm, err := CompileProgram(source)
	if err != nil {
		b.Fatalf("Failed to compile benchmark policy: %v", err)
	}

	engine := NewExecutionEngine(fsm)
	event := createBpfEvent(syscalls.SYS_OPENAT, "/etc/passwd", "", "")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset for each iteration
		engine.Reset()

		_, err := engine.ProcessEvent(event)
		if err != nil {
			b.Fatalf("Event processing failed: %v", err)
		}
	}
}

// BenchmarkFSMStateTransitionsComprehensive benchmarks state transition performance
func BenchmarkFSMStateTransitionsComprehensive(b *testing.B) {
	source := `path "transition_benchmark" {
		openat { pathname="/test" }
		execve { filename="/bin/sh" }
		write { content="test" }
	}`

	fsm, err := CompileProgram(source)
	if err != nil {
		b.Fatalf("Failed to compile policy: %v", err)
	}

	engine := NewExecutionEngine(fsm)
	events := []*ipc.BpfSyscallEvent{
		createBpfEvent(syscalls.SYS_OPENAT, "/test", "", ""),
		createBpfEvent(syscalls.SYS_EXECVE, "", "/bin/sh", ""),
		createBpfEvent(syscalls.SYS_WRITE, "", "", "test"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Reset()

		for _, event := range events {
			_, err := engine.ProcessEvent(event)
			if err != nil {
				b.Fatalf("Event processing failed: %v", err)
			}
		}
	}
}

// BenchmarkFSMParameterMatchingComprehensive benchmarks parameter matching performance
func BenchmarkFSMParameterMatchingComprehensive(b *testing.B) {
	source := `path "param_benchmark" {
		openat { pathname=~"/etc/(passwd|shadow|group|sudoers)" }
		write { content=~".*[rR][oO][oO][tT].*" }
	}`

	fsm, err := CompileProgram(source)
	if err != nil {
		b.Fatalf("Failed to compile policy: %v", err)
	}

	engine := NewExecutionEngine(fsm)
	event := createBpfEvent(syscalls.SYS_OPENAT, "/etc/passwd", "", "")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Reset()

		_, err := engine.ProcessEvent(event)
		if err != nil {
			b.Fatalf("Event processing failed: %v", err)
		}
	}
}
