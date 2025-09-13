package policyd

import (
	"execray.tracer/pkg/ipc"
	"github.com/sirupsen/logrus"
)

// PolicyEngineWorker manages the execution state of a single policy.
type PolicyEngineWorker struct {
	PolicyId              uint64
	PolicyRoot            *Policy
	pid_execution_tracker map[uint64]map[uint64]struct{}
	executions_state      map[uint64]*Policy
	execution_counter     uint64
	log                   *logrus.Logger
	// Each worker gets a dedicated channel for receiving events.
	eventChan chan ipc.BpfSyscallEvent
}

// NewPolicyEngineWorker creates a new worker, including its event channel.
func NewPolicyEngineWorker(policyId uint64) *PolicyEngineWorker {
	return &PolicyEngineWorker{
		PolicyId:              policyId,
		log:                   logrus.New(),
		pid_execution_tracker: make(map[uint64]map[uint64]struct{}),
		executions_state:      make(map[uint64]*Policy),
		execution_counter:     0,
		// A buffered channel helps absorb bursts of events without dropping them.
		eventChan: make(chan ipc.BpfSyscallEvent, 100),
	}
}

// Start launches the worker's main processing loop in a dedicated goroutine.
func (re *PolicyEngineWorker) Start() {
	re.log.WithField("policyId", re.PolicyId).Info("Worker starting...")
	go func() {
		// This loop will run until the eventChan is closed.
		for event := range re.eventChan {
			re.TraceHandler(event)
		}
		re.log.WithField("policyId", re.PolicyId).Info("Worker stopped.")
	}()
}

// Stop gracefully shuts down the worker by closing its channel.
func (re *PolicyEngineWorker) Stop() {
	close(re.eventChan)
}

// TraceHandler processes a single event. It's called by the worker's own goroutine.
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
					}).Info("Policy matched and completed!")
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
		}
	}
}

func (re *PolicyEngineWorker) generateExecutionId() uint64 {
	re.execution_counter++
	return re.execution_counter
}
