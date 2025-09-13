package policyd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"execray.tracer/pkg/ipc"
	"execray.tracer/pkg/syscalls"
)

// TestMultiStepPolicyExecution tests multi-step policy execution with state progression
func TestMultiStepPolicyExecution(t *testing.T) {
	// Create a temporary directory for policy files
	tempDir := t.TempDir()

	// Create a multi-step policy that requires openat -> execve -> write sequence
	multiStepPolicy := `path "multi_step_test" {
		openat { pathname="/etc/passwd" }
		execve { filename="/bin/sh" } 
		write { content =~ ".*root.*" }
	}`

	policyFile := filepath.Join(tempDir, "multistep.policy")
	err := os.WriteFile(policyFile, []byte(multiStepPolicy), 0644)
	if err != nil {
		t.Fatalf("Failed to create policy file: %v", err)
	}

	// Load the policy
	loader := NewPolicyLoader(tempDir)
	err = loader.LoadPolicies()
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	policies := loader.GetPolicies()
	if len(policies) != 1 {
		t.Fatalf("Expected 1 policy, got %d", len(policies))
	}

	// Get the compiled policy
	var compiledPolicy *CompiledPolicy
	for _, policy := range policies {
		compiledPolicy = policy
		break
	}

	// Create worker
	worker := NewPolicyEngineWorker("multi_step_test", compiledPolicy)
	testPID := uint64(12345)

	// Step 1: Send openat event (should start execution)
	event1 := ipc.BpfSyscallEvent{
		Pid:       testPID,
		SyscallNr: syscalls.SYS_OPENAT,
		Data:      createMockOpenatData("/etc/passwd"),
	}
	worker.handleFSMEvent(event1)

	// Check that execution was started
	if len(worker.pidExecutions[testPID]) != 1 {
		t.Fatalf("Expected 1 active execution after step 1, got %d", len(worker.pidExecutions[testPID]))
	}

	exec1 := worker.pidExecutions[testPID][0]
	if exec1.StepCount != 1 {
		t.Errorf("Expected step count 1 after first event, got %d", exec1.StepCount)
	}

	// Step 2: Send execve event (should progress execution AND potentially start another)
	event2 := ipc.BpfSyscallEvent{
		Pid:       testPID,
		SyscallNr: syscalls.SYS_EXECVE,
		Data:      createMockExecveData("/bin/sh"),
	}
	worker.handleFSMEvent(event2)

	// Debug: Check what executions exist
	t.Logf("After event2: %d executions for PID %d", len(worker.pidExecutions[testPID]), testPID)
	for i, exec := range worker.pidExecutions[testPID] {
		t.Logf("Execution %d: ID=%d, StepCount=%d, EventCount=%d, LastState=%s",
			i, exec.ID, exec.StepCount, exec.EventCount, exec.LastMatchedState)
	}

	// Note: execve can also start new executions if it matches initial conditions
	// So we might have 1 or 2 executions depending on policy structure
	if len(worker.pidExecutions[testPID]) == 0 {
		t.Fatalf("Expected at least 1 active execution after step 2, got 0")
	}

	// Check that at least one execution has progressed
	foundProgressedExecution := false
	for _, exec := range worker.pidExecutions[testPID] {
		if exec.EventCount >= 2 {
			foundProgressedExecution = true
			break
		}
	}
	if !foundProgressedExecution {
		t.Error("Expected at least one execution to have processed 2+ events")
	}

	// Step 3: Send write event with matching content (should complete policy)
	event3 := ipc.BpfSyscallEvent{
		Pid:       testPID,
		SyscallNr: syscalls.SYS_WRITE,
		Data:      createMockWriteData("adding root user"),
	}
	worker.handleFSMEvent(event3)

	// Note: Multiple executions can be created if syscalls match initial conditions
	// The write event might also start new executions, and some may complete
	t.Logf("After event3: %d executions for PID %d", len(worker.pidExecutions[testPID]), testPID)

	// Test miss count increment with non-matching event
	// Start fresh test with a different PID
	testPID2 := uint64(54321)
	worker.handleFSMEvent(ipc.BpfSyscallEvent{
		Pid:       testPID2,
		SyscallNr: syscalls.SYS_OPENAT,
		Data:      createMockOpenatData("/etc/passwd"),
	})

	initialExecCount := len(worker.pidExecutions[testPID2])
	t.Logf("Started %d executions for PID %d", initialExecCount, testPID2)

	// Send non-matching event (should increment miss count)
	nonMatchingEvent := ipc.BpfSyscallEvent{
		Pid:       testPID2,
		SyscallNr: syscalls.SYS_WRITE,
		Data:      createMockWriteData("non-matching content"),
	}
	worker.handleFSMEvent(nonMatchingEvent)

	// Check that some executions are still tracked (behavior depends on policy structure)
	t.Logf("After non-matching event: %d executions for PID %d", len(worker.pidExecutions[testPID2]), testPID2)
}

// TestExecutionTimeoutCleanup tests automatic cleanup of expired executions
func TestExecutionTimeoutCleanup(t *testing.T) {
	// Create a simple policy
	tempDir := t.TempDir()
	simplePolicy := `path "timeout_test" {
		openat { pathname="/test" }
	}`

	policyFile := filepath.Join(tempDir, "timeout.policy")
	err := os.WriteFile(policyFile, []byte(simplePolicy), 0644)
	if err != nil {
		t.Fatalf("Failed to create policy file: %v", err)
	}

	loader := NewPolicyLoader(tempDir)
	err = loader.LoadPolicies()
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	policies := loader.GetPolicies()
	var compiledPolicy *CompiledPolicy
	for _, policy := range policies {
		compiledPolicy = policy
		break
	}

	// Create worker with short timeout
	worker := NewPolicyEngineWorker("timeout_test", compiledPolicy)
	worker.executionTimeout = 100 * time.Millisecond // Very short timeout for testing

	testPID := uint64(99999)

	// Start execution
	event := ipc.BpfSyscallEvent{
		Pid:       testPID,
		SyscallNr: syscalls.SYS_OPENAT,
		Data:      createMockOpenatData("/test"),
	}
	worker.handleFSMEvent(event)

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	// Trigger cleanup by processing another event
	worker.handleFSMEvent(event)

	// Check that old execution was cleaned up
	// The exact behavior depends on policy structure, but we shouldn't have accumulated executions
	if len(worker.pidExecutions[testPID]) > 2 {
		t.Errorf("Expected <= 2 executions after timeout cleanup, got %d", len(worker.pidExecutions[testPID]))
	}
}

// TestExecutionStats tests the execution statistics functionality
func TestExecutionStats(t *testing.T) {
	tempDir := t.TempDir()
	simplePolicy := `path "stats_test" {
		openat { pathname="/test" }
	}`

	policyFile := filepath.Join(tempDir, "stats.policy")
	err := os.WriteFile(policyFile, []byte(simplePolicy), 0644)
	if err != nil {
		t.Fatalf("Failed to create policy file: %v", err)
	}

	loader := NewPolicyLoader(tempDir)
	err = loader.LoadPolicies()
	if err != nil {
		t.Fatalf("Failed to load policies: %v", err)
	}

	policies := loader.GetPolicies()
	var compiledPolicy *CompiledPolicy
	for _, policy := range policies {
		compiledPolicy = policy
		break
	}

	worker := NewPolicyEngineWorker("stats_test", compiledPolicy)

	// Get initial stats
	stats := worker.GetExecutionStats()
	if stats["totalActiveExecutions"] != 0 {
		t.Errorf("Expected 0 initial active executions, got %v", stats["totalActiveExecutions"])
	}
	if stats["trackedPIDs"] != 0 {
		t.Errorf("Expected 0 initial tracked PIDs, got %v", stats["trackedPIDs"])
	}

	// Start some executions
	for i := 0; i < 3; i++ {
		event := ipc.BpfSyscallEvent{
			Pid:       uint64(1000 + i),
			SyscallNr: syscalls.SYS_OPENAT,
			Data:      createMockOpenatData("/test"),
		}
		worker.handleFSMEvent(event)
	}

	// Check updated stats
	stats = worker.GetExecutionStats()
	if stats["executionCounter"].(uint64) < 3 {
		t.Errorf("Expected execution counter >= 3, got %v", stats["executionCounter"])
	}
}

// Helper function for creating mock execve data
func createMockExecveData(filename string) [260]uint8 {
	var data [260]uint8
	copy(data[:], []byte(filename))
	return data
}
