package policyd

import (
	"errors"

	"execray.tracer/pkg/ipc"
)

// Policy represents a single node in a policy's Finite State Machine (FSM).
type Policy struct {
	SyscallNr   uint64 // The syscall number this node matches.
	Name        string
	Description string
	Action      string  // "log", "alert" - typically used on the final node.
	Next        *Policy // Pointer to the next state in the FSM. If nil, this is the end of the policy chain.
}

// EvaluatePolicyOnEvent checks if the given event matches the current policy node.
func (p *Policy) EvaluatePolicyOnEvent(event ipc.BpfSyscallEvent) (*Policy, error) {
	if p.SyscallNr == event.SyscallNr {
		return p.Next, nil
	}
	return nil, errors.New("syscall mismatch")
}
