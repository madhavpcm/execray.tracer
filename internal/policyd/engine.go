package policyd

import (
	"fmt"
	"sync"
	"time"

	"execray.tracer/pkg/ipc"
	"github.com/sirupsen/logrus"
)

// PolicyEngine is the central daemon that oversees all policies and workers.
type PolicyEngine struct {
	Workers    map[string]*PolicyEngineWorker // Changed to string keys for policy IDs
	Pids       sync.Map
	workerMu   sync.RWMutex
	log        *logrus.Logger
	loader     *PolicyLoader
	ConfigPath string
}

// NewPolicyEngine creates and initializes the main policy engine.
func NewPolicyEngine(configPath string) *PolicyEngine {
	engine := &PolicyEngine{
		Workers:    make(map[string]*PolicyEngineWorker),
		log:        logrus.New(),
		ConfigPath: configPath,
	}

	// Initialize policy loader if config path is provided
	if configPath != "" {
		engine.loader = NewPolicyLoader(configPath)
	}

	return engine
}

// LoadPolicies loads all policies from the config path and creates workers
func (pe *PolicyEngine) LoadPolicies() error {
	if pe.loader == nil {
		pe.log.Warn("No policy loader configured, skipping policy loading")
		return nil
	}

	// Load policies from files
	if err := pe.loader.LoadPolicies(); err != nil {
		return err
	}

	// Clear existing workers
	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()

	// Stop existing workers
	for _, worker := range pe.Workers {
		worker.Stop()
	}
	pe.Workers = make(map[string]*PolicyEngineWorker)

	// Create workers for loaded policies
	policies := pe.loader.GetPolicies()
	for id, policy := range policies {
		worker := NewPolicyEngineWorker(id, policy)
		pe.Workers[id] = worker
		worker.Start()

		pe.log.WithFields(logrus.Fields{
			"policyId": id,
			"states":   len(policy.FSM.States),
		}).Info("Policy worker started")
	}

	return nil
}

// StartPolicyWatcher starts the policy file watcher for hot-reloading
func (pe *PolicyEngine) StartPolicyWatcher() {
	if pe.loader == nil {
		return
	}

	pe.loader.StartWatcher()

	// Start a goroutine to periodically refresh workers when policies change
	go func() {
		ticker := time.NewTicker(10 * time.Second) // Check for worker refresh every 10 seconds
		defer ticker.Stop()

		for range ticker.C {
			if err := pe.RefreshPolicies(); err != nil {
				pe.log.WithError(err).Error("Failed to refresh policies")
			}
		}
	}()
}

// RefreshPolicies checks for policy changes and updates workers accordingly
func (pe *PolicyEngine) RefreshPolicies() error {
	if pe.loader == nil {
		return nil
	}

	policies := pe.loader.GetPolicies()

	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()

	// Check for new or updated policies
	for id, policy := range policies {
		if existingWorker, exists := pe.Workers[id]; exists {
			// Check if policy has been updated (simple check by comparing FSM state count)
			if len(existingWorker.CompiledPolicy.FSM.States) != len(policy.FSM.States) {
				pe.log.WithField("policyId", id).Info("Policy updated, restarting worker")
				existingWorker.Stop()
				newWorker := NewPolicyEngineWorker(id, policy)
				pe.Workers[id] = newWorker
				newWorker.Start()
			}
		} else {
			// New policy
			pe.log.WithField("policyId", id).Info("New policy detected, starting worker")
			worker := NewPolicyEngineWorker(id, policy)
			pe.Workers[id] = worker
			worker.Start()
		}
	}

	// Check for removed policies
	for id, worker := range pe.Workers {
		if _, exists := policies[id]; !exists {
			pe.log.WithField("policyId", id).Info("Policy removed, stopping worker")
			worker.Stop()
			delete(pe.Workers, id)
		}
	}

	return nil
}

// RegisterPolicy creates a new worker, adds it, and starts its goroutine.
// This method is kept for backward compatibility but enhanced for FSM support
func (pe *PolicyEngine) RegisterPolicy(policyId string, compiledPolicy *CompiledPolicy) {
	worker := NewPolicyEngineWorker(policyId, compiledPolicy)

	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()
	pe.Workers[policyId] = worker
	worker.Start()
}

// UnregisterPolicy stops a worker's goroutine and removes it from the engine.
func (pe *PolicyEngine) UnregisterPolicy(policyId string) {
	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()
	if worker, exists := pe.Workers[policyId]; exists {
		worker.Stop()
		delete(pe.Workers, policyId)
		pe.log.WithField("policyId", policyId).Info("Unregistered and stopped policy worker.")
	}
}

// GetWorkerInfo returns information about loaded workers
func (pe *PolicyEngine) GetWorkerInfo() map[string]string {
	pe.workerMu.RLock()
	defer pe.workerMu.RUnlock()

	info := make(map[string]string)
	for id, worker := range pe.Workers {
		if worker.CompiledPolicy != nil {
			info[id] = fmt.Sprintf("%d FSM states from %s",
				len(worker.CompiledPolicy.FSM.States),
				worker.CompiledPolicy.SourceFile,
			)
		} else {
			info[id] = "legacy policy"
		}
	}
	return info
}

// GetWorkerCount returns the number of active workers
func (pe *PolicyEngine) GetWorkerCount() int {
	pe.workerMu.RLock()
	defer pe.workerMu.RUnlock()
	return len(pe.Workers)
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
