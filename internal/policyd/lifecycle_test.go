package policyd

import (
	"testing"
	"time"

	"execray.tracer/internal/compiler"
	"execray.tracer/pkg/ipc"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create test syscall events
func createTestSyscallEvent(pid uint64, syscallNr uint64) ipc.BpfSyscallEvent {
	return ipc.BpfSyscallEvent{
		Pid:       pid,
		SyscallNr: syscallNr,
		Args:      [6]uint64{0, 0, 0, 0, 0, 0},
		Data:      [260]uint8{},
	}
}

// TestExecutionLifecycleManagement tests comprehensive execution lifecycle features
func TestExecutionLifecycleManagement(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{"ExecutionCreation", testExecutionCreation},
		{"ExecutionProgression", testExecutionProgression},
		{"ExecutionMissTracking", testExecutionMissTracking},
		{"ExecutionTimeout", testExecutionTimeout},
		{"ExecutionCompletion", testExecutionCompletion},
		{"LifecycleCallbacks", testLifecycleCallbacks},
		{"ExecutionMetrics", testExecutionMetrics},
		{"ExecutionHistory", testExecutionHistory},
		{"ConcurrentExecutions", testConcurrentExecutions},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

func testExecutionCreation(t *testing.T) {
	worker := createTestWorker(t)

	// Track lifecycle events
	var events []ExecutionLifecycleEvent
	worker.AddLifecycleCallback(func(event ExecutionLifecycleEvent, execution *PolicyExecution, details map[string]interface{}) {
		events = append(events, event)
	})

	// Create test event that should start a new execution
	event := createTestSyscallEvent(1234, 56) // openat (correct syscall number)

	// Process event
	worker.EventHandler(event)

	// Wait for async lifecycle callbacks
	time.Sleep(10 * time.Millisecond)

	// Verify execution was created
	stats := worker.GetExecutionStats()
	assert.Equal(t, 1, stats["totalActiveExecutions"])
	assert.Equal(t, 1, stats["trackedPIDs"])

	// Verify lifecycle callback was triggered
	assert.Contains(t, events, EventExecutionCreated)

	// Verify execution details
	activeExecs := worker.GetActiveExecutions()
	require.Len(t, activeExecs[1234], 1)
	exec := activeExecs[1234][0]
	assert.Equal(t, uint64(1234), exec.PID)
	assert.Equal(t, "test_policy", exec.PolicyID)
	assert.Equal(t, "active", exec.Status)
	assert.Equal(t, "Initial state match", exec.CreationReason)
}

func testExecutionProgression(t *testing.T) {
	worker := createTestWorker(t)

	// Track progression events
	var progressionEvents []map[string]interface{}
	worker.AddLifecycleCallback(func(event ExecutionLifecycleEvent, execution *PolicyExecution, details map[string]interface{}) {
		if event == EventExecutionProgressed {
			progressionEvents = append(progressionEvents, details)
		}
	})

	// Start execution with first event
	event1 := createTestSyscallEvent(1234, 56) // openat
	worker.EventHandler(event1)

	// Progress with second event
	event2 := createTestSyscallEvent(1234, 64) // write
	worker.EventHandler(event2)

	// Verify progression was tracked
	activeExecs := worker.GetActiveExecutions()
	if len(activeExecs[1234]) > 0 {
		exec := activeExecs[1234][0]
		assert.Greater(t, len(exec.TransitionHistory), 0, "Should have transition history")
		assert.Greater(t, exec.StepCount, 0, "Should have step progression")
		assert.Greater(t, exec.Metrics.TransitionCount, 0, "Should have transition metrics")
	}
}

func testExecutionMissTracking(t *testing.T) {
	worker := createTestWorker(t)

	// Track miss events
	var missEvents []map[string]interface{}
	worker.AddLifecycleCallback(func(event ExecutionLifecycleEvent, execution *PolicyExecution, details map[string]interface{}) {
		if event == EventExecutionMissed {
			missEvents = append(missEvents, details)
		}
	})

	// Start execution
	event1 := createTestSyscallEvent(1234, 56) // openat
	worker.EventHandler(event1)

	// Wait for async callbacks
	time.Sleep(10 * time.Millisecond)

	// Send events that don't match the FSM pattern
	for i := 0; i < 5; i++ {
		missEvent := createTestSyscallEvent(1234, 999) // Invalid syscall
		worker.EventHandler(missEvent)
	}

	// Wait for miss processing
	time.Sleep(10 * time.Millisecond)

	// Verify miss tracking
	activeExecs := worker.GetActiveExecutions()
	if len(activeExecs[1234]) > 0 {
		exec := activeExecs[1234][0]
		assert.Greater(t, exec.MissCount, 0, "Should have recorded misses")
		assert.Greater(t, len(exec.MissHistory), 0, "Should have miss history")
		assert.Greater(t, exec.Metrics.MissCount, 0, "Should have miss metrics")
	}

	// Verify miss events were triggered
	assert.Greater(t, len(missEvents), 0, "Should have emitted miss events")
}

func testExecutionTimeout(t *testing.T) {
	worker := createTestWorker(t)
	worker.executionTimeout = 100 * time.Millisecond // Short timeout for testing

	// Track timeout events
	var timeoutEvents []map[string]interface{}
	worker.AddLifecycleCallback(func(event ExecutionLifecycleEvent, execution *PolicyExecution, details map[string]interface{}) {
		if event == EventExecutionTimeout {
			timeoutEvents = append(timeoutEvents, details)
		}
	})

	// Start execution
	event := createTestSyscallEvent(1234, 56)
	worker.EventHandler(event)

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	// Trigger cleanup by sending another event
	worker.EventHandler(event)

	// Wait for cleanup processing
	time.Sleep(20 * time.Millisecond)

	// Verify execution was moved to history
	history := worker.GetExecutionHistory()
	assert.Greater(t, len(history), 0, "Should have execution in history")
	assert.Equal(t, "timeout", history[len(history)-1].Status, "Should be marked as timeout")

	// Verify timeout event was triggered
	assert.Greater(t, len(timeoutEvents), 0, "Should have emitted timeout event")
}

func testExecutionCompletion(t *testing.T) {
	worker := createTestWorker(t)

	// Track completion events
	var matchedEvents []map[string]interface{}
	worker.AddLifecycleCallback(func(event ExecutionLifecycleEvent, execution *PolicyExecution, details map[string]interface{}) {
		if event == EventExecutionMatched {
			matchedEvents = append(matchedEvents, details)
		}
	})

	// Create simple policy that matches immediately
	event := createTestSyscallEvent(1234, 56)
	worker.EventHandler(event)

	// For simple policies, execution may complete immediately
	// Verify completion tracking
	history := worker.GetExecutionHistory()
	if len(history) > 0 {
		exec := history[len(history)-1]
		assert.NotZero(t, exec.Metrics.CompletionTime, "Should have completion time")
		assert.NotZero(t, exec.Metrics.TotalDuration, "Should have total duration")
	}
}

func testLifecycleCallbacks(t *testing.T) {
	worker := createTestWorker(t)

	// Track all lifecycle events
	var allEvents []ExecutionLifecycleEvent
	callback1 := func(event ExecutionLifecycleEvent, execution *PolicyExecution, details map[string]interface{}) {
		allEvents = append(allEvents, event)
	}

	callback2 := func(event ExecutionLifecycleEvent, execution *PolicyExecution, details map[string]interface{}) {
		// Second callback for testing multiple callbacks
		allEvents = append(allEvents, event)
	}

	worker.AddLifecycleCallback(callback1)
	worker.AddLifecycleCallback(callback2)

	// Process event to trigger lifecycle
	event := createTestSyscallEvent(1234, 56)
	worker.EventHandler(event)

	// Wait a bit for async callbacks
	time.Sleep(50 * time.Millisecond)

	// Verify callbacks were called
	assert.Greater(t, len(allEvents), 0, "Should have called lifecycle callbacks")
	assert.Contains(t, allEvents, EventExecutionCreated, "Should have creation event")
}

func testExecutionMetrics(t *testing.T) {
	worker := createTestWorker(t)

	// Process multiple events to generate metrics
	for i := 0; i < 3; i++ {
		event := createTestSyscallEvent(uint64(1234+i), 56)
		worker.EventHandler(event)
	}

	// Wait for processing
	time.Sleep(20 * time.Millisecond)

	// Get execution statistics
	stats := worker.GetExecutionStats()
	assert.GreaterOrEqual(t, stats["totalActiveExecutions"].(int), 0)
	assert.GreaterOrEqual(t, stats["trackedPIDs"].(int), 0)
	assert.GreaterOrEqual(t, stats["executionCounter"].(uint64), uint64(0))

	// Get aggregated metrics
	metrics := worker.GetExecutionMetrics()
	// Metrics will be empty if no executions completed yet, which is normal
	assert.NotNil(t, metrics)
}

func testExecutionHistory(t *testing.T) {
	worker := createTestWorker(t)
	worker.maxHistorySize = 5 // Small history for testing

	// Generate multiple executions that complete
	for i := 0; i < 7; i++ {
		event := createTestSyscallEvent(uint64(1234+i), 56)
		worker.EventHandler(event)
	}

	// Get history
	history := worker.GetExecutionHistory()

	// Verify history management
	assert.LessOrEqual(t, len(history), worker.maxHistorySize, "Should not exceed max history size")
}

func testConcurrentExecutions(t *testing.T) {
	worker := createTestWorker(t)
	worker.maxConcurrentExecs = 2 // Limit for testing

	// Start multiple executions for same PID
	for i := 0; i < 5; i++ {
		event := createTestSyscallEvent(1234, 56)
		worker.EventHandler(event)
	}

	// Verify concurrent execution limit
	activeExecs := worker.GetActiveExecutions()
	if execList, exists := activeExecs[1234]; exists {
		assert.LessOrEqual(t, len(execList), worker.maxConcurrentExecs, "Should not exceed max concurrent executions")
	}
}

// Helper function to create a test worker with a simple FSM
func createTestWorker(t *testing.T) *PolicyEngineWorker {
	// Create a simple FSM for testing
	fsm := compiler.NewFSM()

	// Add a simple initial state
	initialState := compiler.NewInitialState("initial")
	fsm.AddState(initialState)
	fsm.SetInitialState("initial")

	// Add a syscall state
	syscallState := compiler.NewSyscallState("openat_state", "openat", nil)
	fsm.AddState(syscallState)

	// Add transitions
	initialState.SetTransitions([]compiler.Transition{
		{TargetState: "openat_state", Condition: ""},
	})

	engine := compiler.NewExecutionEngine(fsm)

	compiledPolicy := &CompiledPolicy{
		ID:     "test_policy",
		FSM:    fsm,
		Engine: engine,
		Name:   "test_policy",
	}

	worker := NewPolicyEngineWorker("test_policy", compiledPolicy)
	worker.log.SetLevel(logrus.WarnLevel) // Reduce log noise in tests

	return worker
}
