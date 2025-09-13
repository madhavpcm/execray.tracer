package policyd

import (
	"sync"

	"execray.tracer/pkg/ipc"
	"github.com/sirupsen/logrus"
)

// PolicyEngine is the central daemon that oversees all policies and workers.
type PolicyEngine struct {
	Workers  map[uint64]*PolicyEngineWorker
	Pids     sync.Map
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

// RegisterPolicy creates a new worker, adds it, and starts its goroutine.
func (pe *PolicyEngine) RegisterPolicy(policyId uint64, rootNode *Policy) {
	worker := NewPolicyEngineWorker(policyId)
	worker.PolicyRoot = rootNode

	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()
	pe.Workers[policyId] = worker
	// Launch the worker in its own goroutine to listen for events.
	worker.Start()
}

// UnregisterPolicy stops a worker's goroutine and removes it from the engine.
func (pe *PolicyEngine) UnregisterPolicy(policyId uint64) {
	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()
	if worker, exists := pe.Workers[policyId]; exists {
		worker.Stop()
		delete(pe.Workers, policyId)
		pe.log.WithField("policyId", policyId).Info("Unregistered and stopped policy worker.")
	}
}

// Broadcast sends the event to all registered workers via their channels.
func (pe *PolicyEngine) Broadcast(event ipc.BpfSyscallEvent) {
	pe.workerMu.RLock()
	defer pe.workerMu.RUnlock()
	for _, worker := range pe.Workers {
		// Use a non-blocking send to prevent a slow worker from blocking the engine.
		select {
		case worker.eventChan <- event:
			// Event sent successfully.
		default:
			// The worker's channel buffer is full, so we drop the event for this worker.
			pe.log.WithField("policyId", worker.PolicyId).Warn("Worker channel full. Dropping event.")
		}
	}
}

// HandleEvent is the main entry point for incoming syscall events.
func (pe *PolicyEngine) HandleEvent(event ipc.BpfSyscallEvent) {
	if _, isTracked := pe.Pids.Load(event.Pid); isTracked {
		pe.Broadcast(event)
	}
}

// TrackPid adds a PID to the master list of monitored processes.
func (pe *PolicyEngine) TrackPid(pid uint64) {
	pe.Pids.Store(pid, true)
	pe.log.WithField("pid", pid).Info("Started tracking new PID.")
}

// UntrackPid removes a PID from the master list.
func (pe *PolicyEngine) UntrackPid(pid uint64) {
	pe.Pids.Delete(pid)
	pe.log.WithField("pid", pid).Info("Stopped tracking new PID.")
}

// Shutdown gracefully stops all running worker goroutines.
func (pe *PolicyEngine) Shutdown() {
	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()
	pe.log.Info("Shutting down all policy workers...")
	for _, worker := range pe.Workers {
		worker.Stop()
	}
}
