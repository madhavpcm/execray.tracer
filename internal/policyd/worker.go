package policyd

import (
	"fmt"
	"sync"
	"time"

	"execray.tracer/internal/compiler"
	"execray.tracer/pkg/ipc"
	"github.com/sirupsen/logrus"
)

// ExecutionLifecycleEvent represents different types of execution lifecycle events
type ExecutionLifecycleEvent string

const (
	EventExecutionCreated    ExecutionLifecycleEvent = "EXECUTION_CREATED"
	EventExecutionProgressed ExecutionLifecycleEvent = "EXECUTION_PROGRESSED"
	EventExecutionMatched    ExecutionLifecycleEvent = "EXECUTION_MATCHED"
	EventExecutionMissed     ExecutionLifecycleEvent = "EXECUTION_MISSED"
	EventExecutionCleaned    ExecutionLifecycleEvent = "EXECUTION_CLEANED"
	EventExecutionTimeout    ExecutionLifecycleEvent = "EXECUTION_TIMEOUT"
)

// ExecutionTransition represents a state transition in the execution
type ExecutionTransition struct {
	Timestamp          time.Time
	FromState          string
	ToState            string
	Event              *ipc.BpfSyscallEvent
	Success            bool
	MissReason         string
	TransitionDuration time.Duration
}

// ExecutionMissType categorizes different types of execution misses
type ExecutionMissType string

const (
	MissTypeStateMismatch ExecutionMissType = "STATE_MISMATCH"
	MissTypeParameterFail ExecutionMissType = "PARAMETER_FAIL"
	MissTypeEngineError   ExecutionMissType = "ENGINE_ERROR"
	MissTypeTimeout       ExecutionMissType = "TIMEOUT"
)

// ExecutionMiss represents a detailed record of an execution miss
type ExecutionMiss struct {
	Timestamp    time.Time
	MissType     ExecutionMissType
	Reason       string
	CurrentState string
	Event        *ipc.BpfSyscallEvent
}

// ExecutionMetrics tracks performance and behavior metrics for an execution
type ExecutionMetrics struct {
	CreationTime          time.Time
	CompletionTime        time.Time
	TotalDuration         time.Duration
	ActiveDuration        time.Duration
	TransitionCount       int
	SuccessfulTransitions int
	FailedTransitions     int
	MissCount             int
	EventsProcessed       int
	AverageTransitionTime time.Duration
}

// PolicyExecution represents an active execution of a policy for a specific PID
type PolicyExecution struct {
	ID               uint64
	PID              uint64
	PolicyID         string
	Engine           *compiler.ExecutionEngine
	MissCount        int
	MaxMissCount     int
	ExecutionPath    []string
	LastMatchedState string
	StartTime        time.Time
	LastActivity     time.Time
	EventCount       int
	StepCount        int // Number of successful state transitions

	// Enhanced lifecycle tracking
	TransitionHistory []ExecutionTransition
	MissHistory       []ExecutionMiss
	Metrics           ExecutionMetrics
	Status            string       // "active", "matched", "failed", "timeout"
	CreationReason    string       // Why this execution was created
	mu                sync.RWMutex // Protects concurrent access to execution data
}

// LifecycleCallback represents a function that handles execution lifecycle events
type LifecycleCallback func(event ExecutionLifecycleEvent, execution *PolicyExecution, details map[string]interface{})

// PolicyEngineWorker manages the execution state of a single compiled policy.
type PolicyEngineWorker struct {
	PolicyId       string
	CompiledPolicy *CompiledPolicy
	// Legacy support
	PolicyRoot *Policy
	// FSM-based execution tracking
	pidExecutions    map[uint64][]*PolicyExecution
	executionCounter uint64
	// Configurable parameters
	maxMissCount       int
	maxConcurrentExecs int
	executionTimeout   time.Duration
	log                *logrus.Logger
	// Each worker gets a dedicated channel for receiving events.
	eventChan chan ipc.BpfSyscallEvent

	// Enhanced lifecycle management
	lifecycleCallbacks []LifecycleCallback
	executionHistory   []*PolicyExecution // Completed executions for analysis
	maxHistorySize     int
	mu                 sync.RWMutex // Protects worker state
}

// NewPolicyEngineWorker creates a new worker for a compiled policy.
func NewPolicyEngineWorker(policyId string, compiledPolicy *CompiledPolicy) *PolicyEngineWorker {
	return &PolicyEngineWorker{
		PolicyId:           policyId,
		CompiledPolicy:     compiledPolicy,
		log:                logrus.New(),
		pidExecutions:      make(map[uint64][]*PolicyExecution),
		executionCounter:   0,
		maxMissCount:       10,               // Configurable threshold
		maxConcurrentExecs: 5,                // Max concurrent executions per PID
		executionTimeout:   30 * time.Second, // Execution timeout
		// A buffered channel helps absorb bursts of events without dropping them.
		eventChan:          make(chan ipc.BpfSyscallEvent, 256),
		lifecycleCallbacks: make([]LifecycleCallback, 0),
		executionHistory:   make([]*PolicyExecution, 0),
		maxHistorySize:     1000, // Keep last 1000 completed executions
	}
}

// NewLegacyPolicyEngineWorker creates a new worker with legacy Policy support
func NewLegacyPolicyEngineWorker(policyId uint64) *PolicyEngineWorker {
	return &PolicyEngineWorker{
		PolicyId:         fmt.Sprintf("legacy_%d", policyId),
		log:              logrus.New(),
		pidExecutions:    make(map[uint64][]*PolicyExecution),
		executionCounter: 0,
		maxMissCount:     10,
		eventChan:        make(chan ipc.BpfSyscallEvent, 256),
	}
}

// AddLifecycleCallback registers a callback for execution lifecycle events
func (re *PolicyEngineWorker) AddLifecycleCallback(callback LifecycleCallback) {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.lifecycleCallbacks = append(re.lifecycleCallbacks, callback)
}

// emitLifecycleEvent sends a lifecycle event to all registered callbacks
func (re *PolicyEngineWorker) emitLifecycleEvent(event ExecutionLifecycleEvent, execution *PolicyExecution, details map[string]interface{}) {
	re.mu.RLock()
	callbacks := make([]LifecycleCallback, len(re.lifecycleCallbacks))
	copy(callbacks, re.lifecycleCallbacks)
	re.mu.RUnlock()

	for _, callback := range callbacks {
		go func(cb LifecycleCallback) {
			defer func() {
				if r := recover(); r != nil {
					re.log.WithFields(logrus.Fields{
						"policyId": re.PolicyId,
						"event":    event,
						"error":    r,
					}).Error("Lifecycle callback panic")
				}
			}()
			cb(event, execution, details)
		}(callback)
	}
}

// createExecution creates a new policy execution with enhanced tracking
func (re *PolicyEngineWorker) createExecution(pid uint64, engine *compiler.ExecutionEngine, creationReason string) *PolicyExecution {
	re.executionCounter++
	now := time.Now()

	execution := &PolicyExecution{
		ID:                re.executionCounter,
		PID:               pid,
		PolicyID:          re.PolicyId,
		Engine:            engine,
		MissCount:         0,
		MaxMissCount:      re.maxMissCount,
		ExecutionPath:     make([]string, 0),
		LastMatchedState:  "",
		StartTime:         now,
		LastActivity:      now,
		EventCount:        0,
		StepCount:         0,
		TransitionHistory: make([]ExecutionTransition, 0),
		MissHistory:       make([]ExecutionMiss, 0),
		Status:            "active",
		CreationReason:    creationReason,
		Metrics: ExecutionMetrics{
			CreationTime: now,
		},
	}

	// Emit creation event
	re.emitLifecycleEvent(EventExecutionCreated, execution, map[string]interface{}{
		"reason": creationReason,
		"pid":    pid,
	})

	return execution
}

// recordTransition records a state transition in the execution history
func (re *PolicyEngineWorker) recordTransition(execution *PolicyExecution, fromState, toState string, event *ipc.BpfSyscallEvent, success bool, missReason string) {
	execution.mu.Lock()
	defer execution.mu.Unlock()

	now := time.Now()
	var transitionDuration time.Duration
	if len(execution.TransitionHistory) > 0 {
		lastTransition := execution.TransitionHistory[len(execution.TransitionHistory)-1]
		transitionDuration = now.Sub(lastTransition.Timestamp)
	}

	transition := ExecutionTransition{
		Timestamp:          now,
		FromState:          fromState,
		ToState:            toState,
		Event:              event,
		Success:            success,
		MissReason:         missReason,
		TransitionDuration: transitionDuration,
	}

	execution.TransitionHistory = append(execution.TransitionHistory, transition)

	// Update metrics
	execution.Metrics.TransitionCount++
	if success {
		execution.Metrics.SuccessfulTransitions++
	} else {
		execution.Metrics.FailedTransitions++
	}

	// Calculate average transition time
	if execution.Metrics.TransitionCount > 0 {
		totalTime := time.Duration(0)
		for _, t := range execution.TransitionHistory {
			totalTime += t.TransitionDuration
		}
		execution.Metrics.AverageTransitionTime = totalTime / time.Duration(execution.Metrics.TransitionCount)
	}
}

// recordMiss records a detailed miss in the execution history
func (re *PolicyEngineWorker) recordMiss(execution *PolicyExecution, missType ExecutionMissType, reason string, currentState string, event *ipc.BpfSyscallEvent) {
	execution.mu.Lock()
	defer execution.mu.Unlock()

	miss := ExecutionMiss{
		Timestamp:    time.Now(),
		MissType:     missType,
		Reason:       reason,
		CurrentState: currentState,
		Event:        event,
	}

	execution.MissHistory = append(execution.MissHistory, miss)
	execution.Metrics.MissCount++

	// Emit miss event
	re.emitLifecycleEvent(EventExecutionMissed, execution, map[string]interface{}{
		"missType":     missType,
		"reason":       reason,
		"currentState": currentState,
		"missCount":    execution.MissCount,
	})
}

// completeExecution marks an execution as completed and moves it to history
func (re *PolicyEngineWorker) completeExecution(execution *PolicyExecution, completionStatus string) {
	execution.mu.Lock()
	execution.Status = completionStatus
	execution.Metrics.CompletionTime = time.Now()
	execution.Metrics.TotalDuration = execution.Metrics.CompletionTime.Sub(execution.Metrics.CreationTime)
	execution.Metrics.ActiveDuration = execution.LastActivity.Sub(execution.Metrics.CreationTime)
	execution.Metrics.EventsProcessed = execution.EventCount
	execution.mu.Unlock()

	// Move to history
	re.mu.Lock()
	re.executionHistory = append(re.executionHistory, execution)
	// Trim history if too large
	if len(re.executionHistory) > re.maxHistorySize {
		re.executionHistory = re.executionHistory[len(re.executionHistory)-re.maxHistorySize:]
	}
	re.mu.Unlock()

	// Emit appropriate lifecycle event
	var event ExecutionLifecycleEvent
	switch completionStatus {
	case "matched":
		event = EventExecutionMatched
	case "timeout":
		event = EventExecutionTimeout
	default:
		event = EventExecutionCleaned
	}

	re.emitLifecycleEvent(event, execution, map[string]interface{}{
		"completionStatus": completionStatus,
		"duration":         execution.Metrics.TotalDuration,
		"stepCount":        execution.StepCount,
		"eventCount":       execution.EventCount,
		"missCount":        execution.MissCount,
	})
}

// Start launches the worker's main processing loop in a dedicated goroutine.
func (re *PolicyEngineWorker) Start() {
	re.log.WithField("policyId", re.PolicyId).Info("Worker starting...")
	go func() {
		// This loop will run until the eventChan is closed.
		for event := range re.eventChan {
			re.EventHandler(event)
		}
		re.log.WithField("policyId", re.PolicyId).Info("Worker stopped.")
	}()
}

// Stop gracefully shuts down the worker by closing its channel.
func (re *PolicyEngineWorker) Stop() {
	close(re.eventChan)
}

// EventHandler processes a single event using FSM execution.
func (re *PolicyEngineWorker) EventHandler(event ipc.BpfSyscallEvent) {
	// Handle FSM-based policy execution
	if re.CompiledPolicy != nil {
		re.handleFSMEvent(event)
	} else if re.PolicyRoot != nil {
		// Fallback to legacy policy handling
		re.handleLegacyEvent(event)
	}
}

// handleFSMEvent processes events using the compiled FSM with enhanced lifecycle management
func (re *PolicyEngineWorker) handleFSMEvent(event ipc.BpfSyscallEvent) {
	now := time.Now()

	// Clean up expired executions first
	// re.cleanupExpiredExecutions(now)

	// Process existing executions for this PID
	if executions, exists := re.pidExecutions[event.Pid]; exists {
		var activeExecutions []*PolicyExecution

		for _, exec := range executions {
			// Update execution activity
			exec.LastActivity = now
			exec.EventCount++

			// Process the event through the FSM
			previousState := exec.Engine.GetCurrentState()
			result, err := exec.Engine.ProcessEvent(&event)

			if err != nil {
				// Record engine error
				re.recordMiss(exec, MissTypeEngineError, err.Error(), previousState, &event)
				re.recordTransition(exec, previousState, previousState, &event, false, err.Error())
				exec.MissCount++

				re.log.WithFields(logrus.Fields{
					"execId":   exec.ID,
					"pid":      event.Pid,
					"error":    err,
					"policyId": re.PolicyId,
				}).Error("FSM execution error")
			} else {
				// Update execution state
				exec.ExecutionPath = result.Path
				exec.LastMatchedState = result.FinalState

				// Check if state progressed
				if result.FinalState != previousState && result.FinalState != "" {
					exec.StepCount++

					// Record successful transition
					re.recordTransition(exec, previousState, result.FinalState, &event, true, "")

					// Emit progression event
					re.emitLifecycleEvent(EventExecutionProgressed, exec, map[string]interface{}{
						"fromState":  previousState,
						"toState":    result.FinalState,
						"stepCount":  exec.StepCount,
						"pathLength": len(result.Path),
					})

					re.log.WithFields(logrus.Fields{
						"execId":     exec.ID,
						"pid":        event.Pid,
						"policyId":   re.PolicyId,
						"fromState":  previousState,
						"toState":    result.FinalState,
						"stepCount":  exec.StepCount,
						"pathLength": len(result.Path),
					}).Debug("Policy execution state progressed")
				}

				if result.Matched {
					// Policy matched successfully!
					re.completeExecution(exec, "matched")

					re.log.WithFields(logrus.Fields{
						"execId":        exec.ID,
						"pid":           event.Pid,
						"policyId":      re.PolicyId,
						"finalState":    result.FinalState,
						"stepCount":     exec.StepCount,
						"eventCount":    exec.EventCount,
						"executionPath": result.Path,
						"duration":      now.Sub(exec.StartTime),
					}).Info("Policy matched successfully!")

					// Don't include completed executions in active list
					continue
				} else if result.ErrorMessage != "" {
					// Record parameter/state mismatch error
					re.recordMiss(exec, MissTypeParameterFail, result.ErrorMessage, result.FinalState, &event)
					re.recordTransition(exec, previousState, result.FinalState, &event, false, result.ErrorMessage)
					exec.MissCount++

					re.log.WithFields(logrus.Fields{
						"execId":       exec.ID,
						"pid":          event.Pid,
						"policyId":     re.PolicyId,
						"missCount":    exec.MissCount,
						"error":        result.ErrorMessage,
						"currentState": result.FinalState,
					}).Debug("Policy execution error")
				} else {
					// Normal progression - don't increment miss count for successful state transitions
					if result.FinalState == previousState {
						// No state change, record state mismatch
						re.recordMiss(exec, MissTypeStateMismatch, "No state progression", result.FinalState, &event)
						re.recordTransition(exec, previousState, result.FinalState, &event, false, "No state progression")
						exec.MissCount++

						re.log.WithFields(logrus.Fields{
							"execId":    exec.ID,
							"pid":       event.Pid,
							"policyId":  re.PolicyId,
							"missCount": exec.MissCount,
							"state":     result.FinalState,
						}).Debug("No state progression, incrementing miss count")
					}
				}
			}

			// Check if execution should continue
			if exec.MissCount >= exec.MaxMissCount {
				re.completeExecution(exec, "failed")

				re.log.WithFields(logrus.Fields{
					"execId":    exec.ID,
					"pid":       event.Pid,
					"policyId":  re.PolicyId,
					"missCount": exec.MissCount,
					"stepCount": exec.StepCount,
					"duration":  now.Sub(exec.StartTime),
				}).Debug("Policy execution exceeded miss threshold, terminating")
			} else {
				// Keep active execution
				activeExecutions = append(activeExecutions, exec)
			}
		}

		// Update active executions
		if len(activeExecutions) > 0 {
			re.pidExecutions[event.Pid] = activeExecutions
		} else {
			delete(re.pidExecutions, event.Pid)
		}
	}

	// Check if we should start a new execution
	if re.shouldStartNewExecution(event.Pid) {
		// Try to start a new execution by testing the initial state
		engine := compiler.NewExecutionEngine(re.CompiledPolicy.FSM)
		result, err := engine.ProcessEvent(&event)
		if err != nil {
			re.log.WithFields(logrus.Fields{
				"pid":      event.Pid,
				"policyId": re.PolicyId,
				"error":    err,
			}).Debug("Failed to start new policy execution")
			return
		}

		// If the event matches the initial state pattern, start a new execution
		if len(result.Path) > 1 || result.Matched { // More than just initial state OR immediate match
			execution := re.createExecution(event.Pid, engine, "Initial state match")
			execution.ExecutionPath = result.Path
			execution.LastMatchedState = result.FinalState
			execution.EventCount = 1

			if result.Matched {
				// Immediate match (single-state policy)
				re.completeExecution(execution, "matched")

				re.log.WithFields(logrus.Fields{
					"execId":     execution.ID,
					"pid":        event.Pid,
					"policyId":   re.PolicyId,
					"finalState": result.FinalState,
					"pathLength": len(result.Path),
				}).Info("Policy matched immediately!")
			} else {
				// Multi-step execution started
				execution.StepCount = 1 // First step completed

				// Add to active executions
				if re.pidExecutions[event.Pid] == nil {
					re.pidExecutions[event.Pid] = make([]*PolicyExecution, 0)
				}
				re.pidExecutions[event.Pid] = append(re.pidExecutions[event.Pid], execution)

				re.log.WithFields(logrus.Fields{
					"execId":             execution.ID,
					"pid":                event.Pid,
					"policyId":           re.PolicyId,
					"initialState":       result.FinalState,
					"stepCount":          execution.StepCount,
					"maxConcurrentExecs": re.maxConcurrentExecs,
				}).Debug("Started new multi-step policy execution")
			}
		}
	}
}

// handleLegacyEvent provides backward compatibility with legacy Policy structures
func (re *PolicyEngineWorker) handleLegacyEvent(event ipc.BpfSyscallEvent) {
	// This is the original implementation for backward compatibility
	re.log.WithField("policyId", re.PolicyId).Debug("Using legacy policy handler")

	if re.PolicyRoot != nil {
		if nextNode, err := re.PolicyRoot.EvaluatePolicyOnEvent(event); err == nil {
			re.log.WithFields(logrus.Fields{
				"pid":      event.Pid,
				"policyId": re.PolicyId,
			}).Info("Legacy policy matched!")
			// Note: Legacy implementation doesn't track state properly
			_ = nextNode
		}
	}
}

// GetExecutionStats returns enhanced statistics about current executions
func (re *PolicyEngineWorker) GetExecutionStats() map[string]interface{} {
	re.mu.RLock()
	defer re.mu.RUnlock()

	stats := make(map[string]interface{})

	totalExecs := 0
	totalPIDs := len(re.pidExecutions)

	for _, executions := range re.pidExecutions {
		totalExecs += len(executions)
	}

	stats["totalActiveExecutions"] = totalExecs
	stats["trackedPIDs"] = totalPIDs
	stats["executionCounter"] = re.executionCounter
	stats["maxMissCount"] = re.maxMissCount
	stats["maxConcurrentExecs"] = re.maxConcurrentExecs
	stats["executionTimeout"] = re.executionTimeout.String()
	stats["completedExecutions"] = len(re.executionHistory)
	stats["lifecycleCallbacks"] = len(re.lifecycleCallbacks)

	return stats
}

// GetExecutionHistory returns the history of completed executions
func (re *PolicyEngineWorker) GetExecutionHistory() []*PolicyExecution {
	re.mu.RLock()
	defer re.mu.RUnlock()

	// Return a copy to prevent external modification
	history := make([]*PolicyExecution, len(re.executionHistory))
	copy(history, re.executionHistory)
	return history
}

// GetActiveExecutions returns a snapshot of currently active executions
func (re *PolicyEngineWorker) GetActiveExecutions() map[uint64][]*PolicyExecution {
	re.mu.RLock()
	defer re.mu.RUnlock()

	// Return a deep copy to prevent external modification
	active := make(map[uint64][]*PolicyExecution)
	for pid, executions := range re.pidExecutions {
		active[pid] = make([]*PolicyExecution, len(executions))
		copy(active[pid], executions)
	}
	return active
}

// GetExecutionMetrics returns aggregated metrics across all executions
func (re *PolicyEngineWorker) GetExecutionMetrics() map[string]interface{} {
	re.mu.RLock()
	defer re.mu.RUnlock()

	metrics := make(map[string]interface{})

	if len(re.executionHistory) == 0 {
		return metrics
	}

	totalDuration := time.Duration(0)
	totalTransitions := 0
	totalMisses := 0
	totalEvents := 0
	matchedCount := 0
	timeoutCount := 0
	failedCount := 0

	for _, exec := range re.executionHistory {
		totalDuration += exec.Metrics.TotalDuration
		totalTransitions += exec.Metrics.TransitionCount
		totalMisses += exec.Metrics.MissCount
		totalEvents += exec.Metrics.EventsProcessed

		switch exec.Status {
		case "matched":
			matchedCount++
		case "timeout":
			timeoutCount++
		case "failed":
			failedCount++
		}
	}

	metrics["averageExecutionDuration"] = totalDuration / time.Duration(len(re.executionHistory))
	metrics["averageTransitionsPerExecution"] = float64(totalTransitions) / float64(len(re.executionHistory))
	metrics["averageMissesPerExecution"] = float64(totalMisses) / float64(len(re.executionHistory))
	metrics["averageEventsPerExecution"] = float64(totalEvents) / float64(len(re.executionHistory))
	metrics["matchedExecutions"] = matchedCount
	metrics["timeoutExecutions"] = timeoutCount
	metrics["failedExecutions"] = failedCount
	metrics["totalCompletedExecutions"] = len(re.executionHistory)

	if totalTransitions > 0 {
		metrics["successRate"] = float64(matchedCount) / float64(len(re.executionHistory))
	}

	return metrics
}

// cleanupExpiredExecutions removes executions that have exceeded the timeout with enhanced lifecycle tracking
func (re *PolicyEngineWorker) cleanupExpiredExecutions(now time.Time) {
	for pid, executions := range re.pidExecutions {
		var activeExecutions []*PolicyExecution

		for _, exec := range executions {
			if now.Sub(exec.LastActivity) <= re.executionTimeout {
				activeExecutions = append(activeExecutions, exec)
			} else {
				// Record timeout miss and complete execution
				re.recordMiss(exec, MissTypeTimeout, "Execution timeout", exec.LastMatchedState, nil)
				re.completeExecution(exec, "timeout")

				re.log.WithFields(logrus.Fields{
					"execId":       exec.ID,
					"pid":          pid,
					"policyId":     re.PolicyId,
					"duration":     now.Sub(exec.StartTime),
					"stepCount":    exec.StepCount,
					"eventCount":   exec.EventCount,
					"lastActivity": exec.LastActivity,
				}).Debug("Policy execution timed out, cleaning up")
			}
		}

		if len(activeExecutions) > 0 {
			re.pidExecutions[pid] = activeExecutions
		} else {
			delete(re.pidExecutions, pid)
		}
	}
}

// shouldStartNewExecution determines if a new execution should be started for the given PID
func (re *PolicyEngineWorker) shouldStartNewExecution(pid uint64) bool {
	executions := re.pidExecutions[pid]

	// Don't exceed maximum concurrent executions per PID
	if len(executions) >= re.maxConcurrentExecs {
		re.log.WithFields(logrus.Fields{
			"pid":                pid,
			"policyId":           re.PolicyId,
			"currentExecs":       len(executions),
			"maxConcurrentExecs": re.maxConcurrentExecs,
		}).Debug("Maximum concurrent executions reached for PID")
		return false
	}

	return true
}
