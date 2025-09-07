package ipc

import (
	"encoding/json"
	"net"
	"sync"
)

type Command struct {
	Action string `json:"action"` // "add" or "remove"
	PID    int    `json:"pid"`
}

type Daemon struct {
	mu   sync.Mutex
	pids map[int]struct{}
}

// Client side
func SendCommand(socketPath string, cmd Command) (string, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(cmd); err != nil {
		return "", err
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}
