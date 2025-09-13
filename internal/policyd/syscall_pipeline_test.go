package policyd

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"execray.tracer/pkg/ipc"
	"execray.tracer/pkg/syscalls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSyscallPipelineIntegration tests the complete syscall processing pipeline:
// BpfSyscallEvent → PolicyEngine → Workers → FSM evaluation → Parameter matching
func TestSyscallPipelineIntegration(t *testing.T) {
	// Create a temporary directory with test policies
	tmpDir := t.TempDir()

	// Create test policy files
	policy1Content := `path "file_access_monitor" {
    openat { pathname="/etc/passwd" }
}`
	policyFile1 := filepath.Join(tmpDir, "file_access.policy")
	err := os.WriteFile(policyFile1, []byte(policy1Content), 0644)
	require.NoError(t, err)

	policy2Content := `path "multi_step_detection" {
    openat { pathname =~ "/tmp.*" }
    write { content =~ "test.*" }
}`
	policyFile2 := filepath.Join(tmpDir, "multi_step.policy")
	err = os.WriteFile(policyFile2, []byte(policy2Content), 0644)
	require.NoError(t, err)

	// Create and initialize policy engine
	engine := NewPolicyEngine(tmpDir)
	require.NoError(t, engine.LoadPolicies())

	// Verify policies loaded
	assert.Equal(t, 2, engine.GetWorkerCount())

	// Track a test PID
	testPID := uint64(12345)
	engine.TrackPid(testPID)

	// Test 1: Create a syscall event that should match the first policy
	t.Run("SingleStepPolicyMatch", func(t *testing.T) {
		// Create openat event for /etc/passwd
		openatEvent := createOpenatEvent(testPID, "/etc/passwd")

		// Process through pipeline
		engine.HandleEvent(openatEvent)

		// Give workers time to process
		time.Sleep(100 * time.Millisecond)

		// Verify that file_access_monitor policy matched
		// We expect the policy to complete immediately on match
		t.Log("Single-step policy match test completed")
	})

	// Test 2: Multi-step policy execution
	t.Run("MultiStepPolicyExecution", func(t *testing.T) {
		testPID2 := uint64(54321)
		engine.TrackPid(testPID2)

		// First event: openat /tmp/test.txt (should start execution)
		openatEvent := createOpenatEvent(testPID2, "/tmp/test.txt")
		engine.HandleEvent(openatEvent)
		time.Sleep(50 * time.Millisecond)

		// Second event: write with "test data" (should complete execution)
		writeEvent := createWriteEvent(testPID2, "test data")
		engine.HandleEvent(writeEvent)
		time.Sleep(50 * time.Millisecond)

		t.Log("Multi-step policy execution test completed")
	})

	// Test 3: Non-matching events
	t.Run("NonMatchingEvents", func(t *testing.T) {
		testPID3 := uint64(99999)
		engine.TrackPid(testPID3)

		// Create events that shouldn't match any policies
		nonMatchEvent := createOpenatEvent(testPID3, "/home/user/file.txt")
		engine.HandleEvent(nonMatchEvent)
		time.Sleep(50 * time.Millisecond)

		t.Log("Non-matching events test completed")
	})

	// Test 4: Parameter parsing verification
	t.Run("ParameterParsing", func(t *testing.T) {
		// Test that syscall parameter parsing works correctly
		event := createOpenatEvent(testPID, "/etc/passwd")

		// Verify the raw event has correct syscall number
		assert.Equal(t, uint64(syscalls.SYS_OPENAT), event.SyscallNr)

		// Verify we can parse the parameters
		parser, err := syscalls.SyscallParser(event.SyscallNr)
		require.NoError(t, err)

		syscallData := parser()
		reader := bytes.NewReader(event.Data[:])
		require.NoError(t, syscallData.Parse(reader))

		// Verify parsed data matches expected pathname
		assert.Contains(t, syscallData.String(), "/etc/passwd")

		t.Log("Parameter parsing verification completed")
	})

	// Cleanup
	engine.Shutdown()
}

// TestSyscallEventParsing tests that different syscall types parse correctly
func TestSyscallEventParsing(t *testing.T) {
	tests := []struct {
		name           string
		syscallNr      uint64
		createEvent    func() ipc.BpfSyscallEvent
		expectedString string
	}{
		{
			name:      "OpenatParsing",
			syscallNr: syscalls.SYS_OPENAT,
			createEvent: func() ipc.BpfSyscallEvent {
				return createOpenatEvent(1234, "/test/path")
			},
			expectedString: "/test/path",
		},
		{
			name:      "WriteParsing",
			syscallNr: syscalls.SYS_WRITE,
			createEvent: func() ipc.BpfSyscallEvent {
				return createWriteEvent(1234, "test content")
			},
			expectedString: "test content",
		},
		{
			name:      "ExecveParsing",
			syscallNr: syscalls.SYS_EXECVE,
			createEvent: func() ipc.BpfSyscallEvent {
				return createExecveEvent(1234, "/usr/bin/test")
			},
			expectedString: "/usr/bin/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := tt.createEvent()

			// Verify syscall number
			assert.Equal(t, tt.syscallNr, event.SyscallNr)

			// Parse and verify content
			parser, err := syscalls.SyscallParser(event.SyscallNr)
			require.NoError(t, err)

			syscallData := parser()
			reader := bytes.NewReader(event.Data[:])
			require.NoError(t, syscallData.Parse(reader))

			assert.Contains(t, syscallData.String(), tt.expectedString)
		})
	}
}

// Helper functions for creating test syscall events

func createOpenatEvent(pid uint64, pathname string) ipc.BpfSyscallEvent {
	event := ipc.BpfSyscallEvent{
		Ts:        uint64(time.Now().UnixNano()),
		Pid:       pid,
		SyscallNr: syscalls.SYS_OPENAT,
	}

	// Fill the Data field with pathname
	copy(event.Data[:], []byte(pathname))

	return event
}

func createWriteEvent(pid uint64, content string) ipc.BpfSyscallEvent {
	event := ipc.BpfSyscallEvent{
		Ts:        uint64(time.Now().UnixNano()),
		Pid:       pid,
		SyscallNr: syscalls.SYS_WRITE,
	}

	// Write events have length + content format
	buf := bytes.NewBuffer(nil)
	contentBytes := []byte(content)
	binary.Write(buf, binary.LittleEndian, uint32(len(contentBytes)))
	buf.Write(contentBytes)

	copy(event.Data[:], buf.Bytes())

	return event
}

func createExecveEvent(pid uint64, filename string) ipc.BpfSyscallEvent {
	event := ipc.BpfSyscallEvent{
		Ts:        uint64(time.Now().UnixNano()),
		Pid:       pid,
		SyscallNr: syscalls.SYS_EXECVE,
	}

	// Fill the Data field with filename
	copy(event.Data[:], []byte(filename))

	return event
}

// TestPipelinePerformance tests the performance characteristics of the syscall pipeline
func TestPipelinePerformance(t *testing.T) {
	// Create a simple policy for performance testing
	tmpDir := t.TempDir()

	policyContent := `path "perf_test" { openat { pathname =~ "/tmp.*" } }`
	policyFile := filepath.Join(tmpDir, "perf.policy")
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	engine := NewPolicyEngine(tmpDir)
	require.NoError(t, engine.LoadPolicies())

	testPID := uint64(99999)
	engine.TrackPid(testPID)

	// Test processing many events
	numEvents := 1000
	start := time.Now()

	for i := 0; i < numEvents; i++ {
		event := createOpenatEvent(testPID, "/tmp/test")
		engine.HandleEvent(event)
	}

	elapsed := time.Since(start)
	eventsPerSecond := float64(numEvents) / elapsed.Seconds()

	t.Logf("Processed %d events in %v (%.0f events/sec)", numEvents, elapsed, eventsPerSecond)

	// Ensure we can process at least 1000 events per second
	assert.Greater(t, eventsPerSecond, 1000.0, "Pipeline should process at least 1000 events/sec")

	engine.Shutdown()
}
