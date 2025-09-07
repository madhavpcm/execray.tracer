package ipc

import (
	"encoding/gob"
	"fmt"
)

// Command is sent from client to daemon.
// Add Pid <>
// Remove Pid <>
// Tracing Enabled/Disabled
type CommandType uint8

const (
	CmdUnknown CommandType = iota
	// CmdSetTracingStatus enables or disables the entire tracer.
	CmdSetTracingStatus
	// CmdAddPid adds a specific process ID to the trace list.
	CmdAddPid
	// CmdRemovePid removes a specific process ID from the trace list.
	CmdRemovePid
)

func (c CommandType) String() string {
	switch c {
	case CmdSetTracingStatus:
		return "CmdSetTracingStatus"
	case CmdAddPid:
		return "CmdAddPid"
	case CmdRemovePid:
		return "CmdRemovePid"
	default:
		return fmt.Sprintf("CmdUnknown(%d)", c)
	}
}

type Command struct {
	Type    CommandType
	Payload any
}

type SetTracingStatusPayload struct {
	Enabled bool
}

type PidPayload struct {
	Pid uint32
}

func Init() {
	// Register all the payload structs for gob encoding.
	gob.Register(SetTracingStatusPayload{})
	gob.Register(PidPayload{})
	gob.Register(BpfSyscallEvent{})
}

type BpfSyscallEvent struct {
	Ts        uint64
	Pid       uint64 // Notice that in bpf struct is 32bit but we have to 64bit align in aarch64
	SyscallNr uint64
	Args      [6]uint64
	// The C union is represented as a byte array.
	// Its size is determined by the largest member of the union.
	Data [260]uint8 // For write_args_t (4 bytes for len + 256 for buf)
}
