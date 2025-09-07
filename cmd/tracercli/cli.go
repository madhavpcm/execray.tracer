package cmd

// In cmd/tracer-cli/main.go

import (
	"encoding/gob"
	"fmt"
	"net"
	"os"

	"execray.tracer/pkg/ipc" // Import the new package
)

// Example of a new 'status' command for the CLI
func main() {
	// ... existing flag parsing ...

	switch command {
	case "add":
		sendCommand(ipc.Command{Action: "add"})
	case "del":
		sendCommand(ipc.Command{Action: "rem"})
	default:
		// ...
	}
}

func sendCommand(cmd ipc.Command) {
	socketPath := "/var/run/execray.tracerd.sock"
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to daemon: %v\n", err)
		fmt.Fprintln(os.Stderr, "Is the daemon running?")
		os.Exit(1)
	}
	defer conn.Close()

	encoder := gob.NewEncoder(conn)
	if err := encoder.Encode(&cmd); err != nil {
		fmt.Fprintf(os.Stderr, "Error sending command to daemon: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully sent command: %s\n", cmd.Action)
	// You could also add logic here to wait for a response from the daemon
}
