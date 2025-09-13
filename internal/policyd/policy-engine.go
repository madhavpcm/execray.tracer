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

type PolicyExecutionIdentifier struct {
	Pid      uint64
	PolicyId uint64
}

// PolicyEngineWorker manages the execution state of a single policy against multiple PIDs.
type PolicyEngineWorker struct {
	PolicyId              uint64
	PolicyRoot            *Policy
	pid_execution_tracker map[uint64]map[uint64]struct{}
	executions_state      map[uint64]*Policy
	execution_counter     uint64
	log                   *logrus.Logger
}

// PolicyEngine is the central daemon that oversees all policies and workers.
type PolicyEngine struct {
	// The single, authoritative map of all active policy workers.
	Workers map[uint64]*PolicyEngineWorker
	// The master set of PIDs that the engine is monitoring.
	Pids map[uint64]struct{}
	// Mutexes to protect shared access to the maps.
	workerMu sync.RWMutex
	pidMu    sync.RWMutex
	log      *logrus.Logger
}

// NewPolicyEngine creates and initializes the main policy engine.
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		Workers: make(map[uint64]*PolicyEngineWorker),
		Pids:    make(map[uint64]struct{}),
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
	pe.pidMu.RLock()
	_, isTracked := pe.Pids[event.Pid]
	pe.pidMu.RUnlock()

	if isTracked {
		// Call the broadcast method directly on the engine.
		pe.Broadcast(event)
	}
}

// TrackPid adds a new PID to the master list of monitored processes.
func (pe *PolicyEngine) TrackPid(pid uint64) {
	pe.pidMu.Lock()
	defer pe.pidMu.Unlock()
	pe.Pids[pid] = struct{}{}
	pe.log.WithField("pid", pid).Info("Started tracking new PID.")
}

// UntrackPid removes a PID from the master list.
func (pe *PolicyEngine) UntrackPid(pid uint64) {
	pe.pidMu.Lock()
	defer pe.pidMu.Unlock()
	delete(pe.Pids, pid)
	pe.log.WithField("pid", pid).Info("Stopped tracking PID.")
}

func NewPolicyEngineWorker(policyId uint64) *PolicyEngineWorker {
	return &PolicyEngineWorker{
		PolicyId:              policyId,
		log:                   logrus.New(),
		pid_execution_tracker: make(map[uint64]map[uint64]struct{}),
		executions_state:      make(map[uint64]*Policy),
		execution_counter:     0,
	}
}

// TraceHandler processes a syscall event and updates the FSM for all relevant policy executions.
func (re *PolicyEngineWorker) TraceHandler(event ipc.BpfSyscallEvent) {
	if active_executions, ok := re.pid_execution_tracker[event.Pid]; ok {
		for exec_id := range active_executions {
			currentState := re.executions_state[exec_id]
			if currentState == nil {
				continue
			}
			if nextNode, err := currentState.EvaluatePolicyOnEvent(event); err == nil {
				re.executions_state[exec_id] = nextNode
				if nextNode == nil {
					re.log.WithFields(logrus.Fields{
						"pid":      event.Pid,
						"policyId": re.PolicyId,
						"action":   currentState.Action,
					}).Info("Policy matched and completed successfully!")
				}
			}
		}
	}
	if re.PolicyRoot != nil {
		if nextNode, err := re.PolicyRoot.EvaluatePolicyOnEvent(event); err == nil {
			exec_id := re.generateExecutionId()
			if _, ok := re.pid_execution_tracker[event.Pid]; !ok {
				re.pid_execution_tracker[event.Pid] = make(map[uint64]struct{})
			}
			re.pid_execution_tracker[event.Pid][exec_id] = struct{}{}
			re.executions_state[exec_id] = nextNode
			if nextNode == nil {
				re.log.WithFields(logrus.Fields{
					"pid":      event.Pid,
					"policyId": re.PolicyId,
					"action":   re.PolicyRoot.Action,
				}).Info("Single-node policy matched and completed successfully!")
			}
		}
	}
}

func (re *PolicyEngineWorker) generateExecutionId() uint64 {
	re.execution_counter++
	return re.execution_counter
}

func (policy *Policy) EvaluatePolicyOnEvent(event ipc.BpfSyscallEvent) (*Policy, error) {
	if policy.SyscallNr == event.SyscallNr {
		return policy.Next, nil
	}
	return nil, errors.New("syscall mismatch")
}
