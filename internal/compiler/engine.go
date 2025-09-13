package compiler

import (
	"fmt"

	"execray.tracer/pkg/ipc"
)

// ExecutionEngine executes FSMs against syscall events
type ExecutionEngine struct {
	fsm *FSM
}

// NewExecutionEngine creates a new FSM execution engine
func NewExecutionEngine(fsm *FSM) *ExecutionEngine {
	return &ExecutionEngine{
		fsm: fsm,
	}
}

// ExecutionResult represents the result of FSM execution
type ExecutionResult struct {
	Matched      bool
	FinalState   string
	Path         []string // States traversed during execution
	ErrorMessage string
}

// ProcessEvent processes a syscall event against the FSM
func (e *ExecutionEngine) ProcessEvent(event *ipc.BpfSyscallEvent) (*ExecutionResult, error) {
	result := &ExecutionResult{
		Matched:    false,
		FinalState: "",
		Path:       []string{},
	}

	// Start from the initial state
	currentStateID := e.fsm.InitialState
	if currentStateID == "" {
		return result, fmt.Errorf("FSM has no initial state")
	}

	// Reset FSM to initial state
	e.fsm.Reset()

	// Process through states
	for {
		result.Path = append(result.Path, currentStateID)

		// Get current state
		currentState, exists := e.fsm.States[currentStateID]
		if !exists {
			result.ErrorMessage = fmt.Sprintf("state %s not found", currentStateID)
			break
		}

		// Evaluate current state against the event
		stateMatches, err := currentState.Evaluate(event)
		if err != nil {
			result.ErrorMessage = fmt.Sprintf("error evaluating state %s: %v", currentStateID, err)
			break
		}

		// If state doesn't match and it's a syscall state, this path fails
		if !stateMatches {
			switch currentState.Type() {
			case SyscallStateType:
				// Syscall states must match to continue
				result.FinalState = currentStateID
				result.Matched = false
				return result, nil
			case ConditionalStateType:
				// For conditional states, handle branching logic
				conditionalState, ok := currentState.(*ConditionalState)
				if !ok {
					result.ErrorMessage = "invalid conditional state"
					break
				}
				// For now, take false branch on non-match
				currentStateID = conditionalState.FalseTransition
				continue
			}
		}

		// Check if we've reached a terminal state
		if currentState.Type() == TerminalStateType {
			terminalState, ok := currentState.(*TerminalState)
			if !ok {
				result.ErrorMessage = "invalid terminal state"
				break
			}
			result.FinalState = currentStateID
			result.Matched = terminalState.MatchResult
			return result, nil
		}

		// Get transitions from current state
		transitions := currentState.GetTransitions()
		if len(transitions) == 0 {
			// No transitions available - end execution
			result.FinalState = currentStateID
			result.Matched = false
			return result, nil
		}

		// For simplicity, take the first valid transition
		// In a more sophisticated implementation, we'd handle multiple transitions,
		// conditional branching, etc.
		nextStateID := transitions[0].TargetState

		// Handle conditional state transitions
		if currentState.Type() == ConditionalStateType {
			conditionalState, ok := currentState.(*ConditionalState)
			if !ok {
				result.ErrorMessage = "invalid conditional state"
				break
			}

			// Evaluate condition (simplified - just check if state matched)
			if stateMatches {
				nextStateID = conditionalState.TrueTransition
			} else {
				nextStateID = conditionalState.FalseTransition
			}
		}

		// Move to next state
		currentStateID = nextStateID
		e.fsm.CurrentState = currentStateID

		// Prevent infinite loops (safety check)
		if len(result.Path) > 100 {
			result.ErrorMessage = "execution path too long (possible infinite loop)"
			break
		}
	}

	result.FinalState = currentStateID
	return result, nil
}

// ProcessEventSequence processes a sequence of syscall events
func (e *ExecutionEngine) ProcessEventSequence(events []*ipc.BpfSyscallEvent) ([]*ExecutionResult, error) {
	results := make([]*ExecutionResult, 0, len(events))

	for i, event := range events {
		result, err := e.ProcessEvent(event)
		if err != nil {
			return results, fmt.Errorf("failed to process event %d: %v", i, err)
		}
		results = append(results, result)

		// If we found a match, we might want to stop processing
		// or reset for the next sequence - this depends on policy semantics
		if result.Matched {
			// For now, continue processing to see if more patterns match
		}
	}

	return results, nil
}

// Reset resets the FSM to its initial state
func (e *ExecutionEngine) Reset() {
	e.fsm.Reset()
}

// GetCurrentState returns the current state of the FSM
func (e *ExecutionEngine) GetCurrentState() string {
	return e.fsm.CurrentState
}

// ValidateFSM validates that the FSM is properly constructed
func (e *ExecutionEngine) ValidateFSM() error {
	if e.fsm == nil {
		return fmt.Errorf("FSM is nil")
	}

	if e.fsm.InitialState == "" {
		return fmt.Errorf("FSM has no initial state")
	}

	if _, exists := e.fsm.States[e.fsm.InitialState]; !exists {
		return fmt.Errorf("initial state %s not found in FSM", e.fsm.InitialState)
	}

	// Check that all transitions point to valid states
	for stateID, state := range e.fsm.States {
		transitions := state.GetTransitions()
		for _, transition := range transitions {
			if _, exists := e.fsm.States[transition.TargetState]; !exists {
				return fmt.Errorf("state %s has transition to non-existent state %s",
					stateID, transition.TargetState)
			}
		}
	}

	return nil
}

// String returns a string representation of the execution engine state
func (e *ExecutionEngine) String() string {
	if e.fsm == nil {
		return "ExecutionEngine[no FSM]"
	}
	return fmt.Sprintf("ExecutionEngine[states: %d, current: %s]",
		len(e.fsm.States), e.fsm.CurrentState)
}
