package ipc

import (
	"encoding/gob"
	"fmt"
	"log"
	"net"
)

// FIXME add flags for this?
const TracerdCommandsSocket = "/var/run/tracerd.commands.sock"
const PolicydCommandsSocket = "/tmp/policyd.commands.sock"
const PolicydTracesSocket = "/tmp/policyd.traces.sock"

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
	// CmdGetPid sends the list of pids in tracking list
	CmdGetPids
)

func (c CommandType) String() string {
	switch c {
	case CmdSetTracingStatus:
		return "CmdSetTracingStatus"
	case CmdAddPid:
		return "CmdAddPid"
	case CmdRemovePid:
		return "CmdRemovePid"
	case CmdGetPids:
		return "CmdGetPids"
	default:
		return fmt.Sprintf("CmdUnknown(%d)", c)
	}
}

type Message struct {
	RequestID       string
	Command         *Command
	CommandResponse *CommandResponse
}

type Command struct {
	Type    CommandType
	Payload any
}

type CommandResponse struct {
	Type    CommandType
	Payload any
}

type SetTracingStatusPayload struct {
	Enabled bool
}

type PidPayload struct {
	Pid uint32
}

// PidListResponse is sent from the daemon back to the client.
type PidListResponse struct {
	PIDs  []uint32 // A list of Process IDs
	Error string   // In case something went wrong
}

func Init() {
	// Register all the payload structs for gob encoding.
	gob.Register(SetTracingStatusPayload{})
	gob.Register(PidPayload{})
	gob.Register(BpfSyscallEvent{})
	gob.Register(PidListResponse{})
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

// Client is responsible for communicating with the tracerd daemon.
type Client struct {
	conn    net.Conn
	encoder *gob.Encoder
	decoder *gob.Decoder
}

// New creates and returns a new Client connected to the daemon's socket.
func NewClient(socket string) (*Client, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon socket at %s: %w", socket, err)
	}

	return &Client{
		conn:    conn,
		encoder: gob.NewEncoder(conn),
		decoder: gob.NewDecoder(conn),
	}, nil
}

// Close terminates the connection to the daemon.
func (c *Client) Close() error {
	return c.conn.Close()
}

// sendCommand is a helper function to wrap and send a command.
func (c *Client) sendCommand(cmdType CommandType, payload any) error {
	cmd := Command{
		Type:    cmdType,
		Payload: payload,
	}
	msg := Message{
		Command: &cmd,
	}
	return c.encoder.Encode(&msg)
}

// AddPid sends a command to the daemon to start tracing a specific PID.
func (c *Client) AddPid(pid uint32) error {
	payload := PidPayload{Pid: pid}
	return c.sendCommand(CmdAddPid, payload)
}

// RemovePid sends a command to the daemon to stop tracing a specific PID.
func (c *Client) RemovePid(pid uint32) error {
	payload := PidPayload{Pid: pid}
	return c.sendCommand(CmdRemovePid, payload)
}

// SetTracingStatus sends a command to enable or disable tracing globally.
func (c *Client) SetTracingStatus(enabled bool) error {
	payload := SetTracingStatusPayload{Enabled: enabled}
	return c.sendCommand(CmdSetTracingStatus, payload)
}

// GetPids sends a command to receive all traced pids
func (c *Client) GetPids() error {
	if err := c.sendCommand(CmdGetPids, nil); err != nil {
		return err
	}
	var response Message
	if err := c.decoder.Decode(&response); err != nil {
		log.Fatalf("Failed to receive response: %v", err)
	}
	if payload, ok := response.CommandResponse.Payload.(PidListResponse); ok {
		log.Printf("Received list of %d PIDs: [%v]", len(payload.PIDs), payload.PIDs)
	} else {
		log.Printf("Received an unexpected message type from the daemon: %v", response)
	}
	return nil
}

// Add this to ipc.go - replace the commented version
func StreamEvents(socketPath string) (chan BpfSyscallEvent, net.Conn, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to traces socket: %w", err)
	}

	decoder := gob.NewDecoder(conn)
	// Buffer
	eventChan := make(chan BpfSyscallEvent, 256)

	go func() {
		defer close(eventChan)
		for {
			var event BpfSyscallEvent
			if err := decoder.Decode(&event); err != nil {
				log.Printf("StreamEvents decode error: %v", err)
				return
			}
			eventChan <- event
		}
	}()

	return eventChan, conn, nil
}

// Add convenience function to create traces client
func NewTracesClient() (*Client, error) {
	conn, err := net.Dial("unix", TracerdCommandsSocket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to traces socket: %w", err)
	}

	return &Client{
		conn:    conn,
		encoder: gob.NewEncoder(conn),
		decoder: gob.NewDecoder(conn),
	}, nil
}
