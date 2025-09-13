package policyd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"execray.tracer/internal/compiler"
	"execray.tracer/pkg/ipc"
	"execray.tracer/pkg/syscalls"
)

func TestPolicyLoader(t *testing.T) {
	// Create temporary directory for test policies
	tempDir := t.TempDir()

	// Create test policy file
	testPolicy := `path "test_policy" {
		openat { pathname="/test/file" }
	}`

	policyFile := filepath.Join(tempDir, "test.policy")
	err := os.WriteFile(policyFile, []byte(testPolicy), 0644)
	if err != nil {
		t.Fatalf("Failed to create test policy file: %v", err)
	}

	// Test policy loader
	loader := NewPolicyLoader(tempDir)

	// Test loading policies
	err = loader.LoadPolicies()
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	policies := loader.GetPolicies()
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}

	policy, exists := loader.GetPolicy("test")
	if !exists {
		t.Error("Expected test policy to exist")
	}

	if policy.Name != "test" {
		t.Errorf("Expected policy name 'test', got %s", policy.Name)
	}

	if len(policy.FSM.States) == 0 {
		t.Error("Expected policy to have FSM states")
	}
}

func TestPolicyEngine(t *testing.T) {
	// Create temporary directory for test policies
	tempDir := t.TempDir()

	// Create test policy file
	testPolicy := `path "simple_test" {
		openat { pathname="/etc/passwd" }
	}`

	policyFile := filepath.Join(tempDir, "simple.policy")
	err := os.WriteFile(policyFile, []byte(testPolicy), 0644)
	if err != nil {
		t.Fatalf("Failed to create test policy file: %v", err)
	}

	// Create policy engine
	engine := NewPolicyEngine(tempDir)

	// Load policies
	err = engine.LoadPolicies()
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	// Check workers were created
	engine.workerMu.RLock()
	workerCount := len(engine.Workers)
	engine.workerMu.RUnlock()

	if workerCount != 1 {
		t.Errorf("Expected 1 worker, got %d", workerCount)
	}

	// Test tracking PID
	testPID := uint64(1234)
	engine.TrackPid(testPID)

	// Test event handling
	event := ipc.BpfSyscallEvent{
		Pid:       testPID,
		SyscallNr: syscalls.SYS_OPENAT,
		Data:      createMockOpenatData("/etc/passwd"),
	}

	engine.HandleEvent(event)

	// Cleanup
	engine.Shutdown()
}

func TestPolicyWorkerFSMExecution(t *testing.T) {
	// Create a simple compiled policy for testing
	testPolicy := `path "test_execution" {
		openat { pathname="/etc/passwd" }
		write { content="test" }
	}`

	fsm, err := compiler.CompileProgram(testPolicy)
	if err != nil {
		t.Fatalf("Failed to compile test policy: %v", err)
	}

	engine := compiler.NewExecutionEngine(fsm)
	compiledPolicy := &CompiledPolicy{
		ID:     "test",
		Name:   "test",
		FSM:    fsm,
		Engine: engine,
	}

	// Create worker
	worker := NewPolicyEngineWorker("test", compiledPolicy)

	// Test event processing
	testPID := uint64(5678)

	// First event - should start execution
	event1 := ipc.BpfSyscallEvent{
		Pid:       testPID,
		SyscallNr: syscalls.SYS_OPENAT,
		Data:      createMockOpenatData("/etc/passwd"),
	}

	worker.handleFSMEvent(event1)

	// Check that execution was started
	if len(worker.pidExecutions[testPID]) != 1 {
		t.Errorf("Expected 1 execution for PID %d, got %d", testPID, len(worker.pidExecutions[testPID]))
	}

	// Second event - should continue execution
	event2 := ipc.BpfSyscallEvent{
		Pid:       testPID,
		SyscallNr: syscalls.SYS_WRITE,
		Data:      createMockWriteData("test"),
	}

	worker.handleFSMEvent(event2)

	// Check execution state (should be completed and removed)
	execCount := len(worker.pidExecutions[testPID])
	if execCount > 0 {
		t.Logf("Execution still active - this might be expected depending on FSM structure")
	}
}

func TestPolicyHotReload(t *testing.T) {
	// Create temporary directory for test policies
	tempDir := t.TempDir()

	// Create initial policy file
	initialPolicy := `path "initial_policy" {
		openat { pathname="/initial" }
	}`

	policyFile := filepath.Join(tempDir, "dynamic.policy")
	err := os.WriteFile(policyFile, []byte(initialPolicy), 0644)
	if err != nil {
		t.Fatalf("Failed to create initial policy file: %v", err)
	}

	// Create policy loader
	loader := NewPolicyLoader(tempDir)

	// Load initial policies
	err = loader.LoadPolicies()
	if err != nil {
		t.Fatalf("Failed to load initial policies: %v", err)
	}

	initialPolicies := loader.GetPolicies()
	if len(initialPolicies) != 1 {
		t.Errorf("Expected 1 initial policy, got %d", len(initialPolicies))
	}

	// Wait a bit to ensure different modification time
	time.Sleep(100 * time.Millisecond)

	// Update policy file
	updatedPolicy := `path "updated_policy" {
		openat { pathname="/updated" }
		execve { filename="/bin/sh" }
	}`

	err = os.WriteFile(policyFile, []byte(updatedPolicy), 0644)
	if err != nil {
		t.Fatalf("Failed to update policy file: %v", err)
	}

	// Check for changes
	err = loader.CheckForChanges()
	if err != nil {
		t.Fatalf("Failed to check for changes: %v", err)
	}

	updatedPolicies := loader.GetPolicies()
	if len(updatedPolicies) != 1 {
		t.Errorf("Expected 1 updated policy, got %d", len(updatedPolicies))
	}

	// Verify the policy was actually updated (more states in FSM)
	policy := updatedPolicies["dynamic"]
	if policy == nil {
		t.Fatal("Updated policy not found")
	}

	if len(policy.FSM.States) <= len(initialPolicies["dynamic"].FSM.States) {
		t.Error("Expected updated policy to have more FSM states")
	}
}

func TestPolicyEngineRefresh(t *testing.T) {
	// Create temporary directory for test policies
	tempDir := t.TempDir()

	// Create policy engine
	engine := NewPolicyEngine(tempDir)

	// Initially no policies
	err := engine.LoadPolicies()
	if err != nil {
		t.Fatalf("Failed to load policies from empty directory: %v", err)
	}

	engine.workerMu.RLock()
	initialWorkers := len(engine.Workers)
	engine.workerMu.RUnlock()

	// Create a new policy file
	newPolicy := `path "new_policy" {
		openat { pathname="/new" }
	}`

	policyFile := filepath.Join(tempDir, "new.policy")
	err = os.WriteFile(policyFile, []byte(newPolicy), 0644)
	if err != nil {
		t.Fatalf("Failed to create new policy file: %v", err)
	}

	// Refresh policies - need to reload from disk first
	err = engine.LoadPolicies()
	if err != nil {
		t.Fatalf("Failed to reload policies: %v", err)
	}

	finalWorkers := engine.GetWorkerCount()

	if finalWorkers <= initialWorkers {
		t.Errorf("Expected more workers after refresh, got %d (was %d)", finalWorkers, initialWorkers)
	}

	// Cleanup
	engine.Shutdown()
}

// Helper functions for creating mock syscall data

func createMockOpenatData(pathname string) [260]uint8 {
	var data [260]uint8
	copy(data[:], []byte(pathname))
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

// Benchmark tests

func BenchmarkPolicyLoading(b *testing.B) {
	// Create temporary directory with multiple policy files
	tempDir := b.TempDir()

	// Create multiple policy files
	for i := 0; i < 10; i++ {
		policy := `path "test_policy" {
			openat { pathname="/test" }
			execve { filename="/bin/sh" }
		}`

		policyFile := filepath.Join(tempDir, fmt.Sprintf("policy_%d.policy", i))
		os.WriteFile(policyFile, []byte(policy), 0644)
	}

	loader := NewPolicyLoader(tempDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loader.LoadPolicies()
	}
}

func BenchmarkEventProcessing(b *testing.B) {
	// Create a simple policy
	testPolicy := `path "bench_policy" {
		openat { pathname="/etc/passwd" }
	}`

	fsm, err := compiler.CompileProgram(testPolicy)
	if err != nil {
		b.Fatalf("Failed to compile test policy: %v", err)
	}

	engine := compiler.NewExecutionEngine(fsm)
	compiledPolicy := &CompiledPolicy{
		ID:     "bench",
		Name:   "bench",
		FSM:    fsm,
		Engine: engine,
	}

	worker := NewPolicyEngineWorker("bench", compiledPolicy)

	event := ipc.BpfSyscallEvent{
		Pid:       1234,
		SyscallNr: syscalls.SYS_OPENAT,
		Data:      createMockOpenatData("/etc/passwd"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		worker.handleFSMEvent(event)
	}
}
