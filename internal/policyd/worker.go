package policyd

import (
	"execray.tracer/pkg/ipc"
	"github.com/sirupsen/logrus"
)

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
