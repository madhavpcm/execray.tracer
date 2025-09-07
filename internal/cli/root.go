package cli

import (
	"fmt"
	"os"
	"strconv"

	"execray.tracer/pkg/ipc"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command for the CLI application.
// It no longer runs the daemon. Its sole purpose is to be the entry
// point for the client-side subcommands.
var rootCmd = &cobra.Command{
	Use:   "./tracercli",
	Short: "A CLI to control and interact with the eBPF tracer daemon.",
	Long: `tracer-cli is a command-line interface that communicates with a running
tracerd daemon over a Unix socket.`,
}

// Execute is the main entry point for the Cobra CLI.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a resource to be traced.",
	Long:  `The add command allows you to add specific resources, like a Process ID (PID), to the daemon's trace list.`,
}
var removeCmd = &cobra.Command{
	Use:   "remove",
	Short: "Stop tracing a resource.",
	Long:  `This remove command allows you to stop tracing specific resources, like a process which died or zombied.`,
}
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Stop tracing a resource.",
	Long:  `This remove command allows you to stop tracing specific resources, like a process which died or zombied.`,
}

var addPidCmd = &cobra.Command{
	Use:   "pid <PID>",
	Short: "Add a specific PID to the trace list.",
	Args:  cobra.ExactArgs(1), // Enforce that exactly one argument is provided.
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Parse the PID from command-line arguments.
		pidVal, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid PID provided: %s", args[0])
		}
		pid := uint32(pidVal)

		// 2. Create a new client to communicate with the daemon.
		c, err := ipc.NewClient()
		if err != nil {
			return err
		}
		defer c.Close()

		// 3. Make the IPC call to add the PID.
		if err := c.AddPid(pid); err != nil {
			return fmt.Errorf("failed to send AddPid command: %w", err)
		}

		fmt.Printf("Successfully requested to add PID %d to the trace list.\n", pid)
		return nil
	},
}
var removePidCmd = &cobra.Command{
	Use:   "pid <PID>",
	Short: "Add a specific PID to the trace list.",
	Args:  cobra.ExactArgs(1), // Enforce that exactly one argument is provided.
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Parse the PID from command-line arguments.
		pidVal, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid PID provided: %s", args[0])
		}
		pid := uint32(pidVal)

		// 2. Create a new client to communicate with the daemon.
		c, err := ipc.NewClient()
		if err != nil {
			return err
		}
		defer c.Close()

		// 3. Make the IPC call to add the PID.
		if err := c.RemovePid(pid); err != nil {
			return fmt.Errorf("failed to send AddPid command: %w", err)
		}

		fmt.Printf("Successfully requested to remove PID %d from the trace list.\n", pid)
		return nil
	},
}
var getPidsCmd = &cobra.Command{
	Use:   "pids",
	Short: "Add a specific PID to the trace list.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// 2. Create a new client to communicate with the daemon.
		c, err := ipc.NewClient()
		if err != nil {
			return err
		}
		defer c.Close()

		// 3. Make the IPC call to add the PID.
		if err := c.GetPids(); err != nil {
			return fmt.Errorf("failed to send getpids command: %w", err)
		}

		return nil
	},
}

func Init() {

	// Add all the client-side subcommands.
	// You will need to move your existing command files (add.go, remove.go, etc.)
	// into this same directory.
	// Example:
	rootCmd.AddCommand(addCmd)
	addCmd.AddCommand(addPidCmd)
	rootCmd.AddCommand(removeCmd)
	removeCmd.AddCommand(removePidCmd)
	rootCmd.AddCommand(getCmd)
	getCmd.AddCommand(getPidsCmd)
	// rootCmd.AddCommand(streamCmd)
}
