package policyd

import (
	"errors"
	"sync"

	"execray.tracer/pkg/ipc"

	"github.com/sirupsen/logrus"
)

// Policy represents a single node in a policy's Finite State Machine (FSM).
type Policy struct {
	SyscallNr   uint64 // The syscall number this node matches.
	Name        string
	Description string
	Action      string  // "log", "alert" - typically used on the final node.
	Next        *Policy // Pointer to the next state in the FSM. If nil, this is the end of the policy chain.
}

// PolicyEngine is the central daemon that oversees all policies and workers.
type PolicyEngine struct {
	// The single, authoritative map of all active policy workers.
	Workers map[uint64]*PolicyEngineWorker
	// The master set of PIDs that the engine is monitoring.
	Pids sync.Map // Replace map and mutex with sync.Map
	// Mutexes to protect shared access to the maps.
	workerMu sync.RWMutex
	log      *logrus.Logger
}

// NewPolicyEngine creates and initializes the main policy engine.
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		Workers: make(map[uint64]*PolicyEngineWorker),
		log:     logrus.New(),
	}
}

// RegisterPolicy creates a new worker for the given policy and adds it to the engine.
func (pe *PolicyEngine) RegisterPolicy(policyId uint64, rootNode *Policy) {
	worker := NewPolicyEngineWorker(policyId)
	worker.PolicyRoot = rootNode

	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()
	pe.Workers[policyId] = worker
	pe.log.WithField("policyId", policyId).Info("Successfully registered new policy.")
}

// Broadcast sends the event to all registered workers.
func (pe *PolicyEngine) Broadcast(event ipc.BpfSyscallEvent) {
	pe.workerMu.RLock()
	defer pe.workerMu.RUnlock()
	for _, worker := range pe.Workers {
		worker.TraceHandler(event)
	}
}

// HandleEvent is the main entry point for incoming syscall events.
func (pe *PolicyEngine) HandleEvent(event ipc.BpfSyscallEvent) {
	// The Load operation is highly optimized and often lock-free.
	if _, isTracked := pe.Pids.Load(event.Pid); isTracked {
		pe.Broadcast(event)
	}
}
func (pe *PolicyEngine) TrackPid(pid uint64) {
	// Use Store to add or update a key. The value can be a simple placeholder.
	pe.Pids.Store(pid, true)
	pe.log.WithField("pid", pid).Info("Started tracking new PID.")
}
func (pe *PolicyEngine) UntrackPid(pid uint64) {
	// Use Delete to remove a key.
	pe.Pids.Delete(pid)
	pe.log.WithField("pid", pid).Info("Stopped tracking PID.")
}

// Dummy Event Handler
func (policy *Policy) EvaluatePolicyOnEvent(event ipc.BpfSyscallEvent) (*Policy, error) {
	if policy.SyscallNr == event.SyscallNr {
		return policy.Next, nil
	}
	return nil, errors.New("syscall mismatch")
}
