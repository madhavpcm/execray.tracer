package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"execray.tracer/internal/policyd"
	"execray.tracer/pkg/ipc"
	"execray.tracer/pkg/syscalls"
)

func main() {
	fmt.Println("=== PolicyD FSM Integration Demo ===")

	// Check if policies directory exists
	policiesDir := "./policies"
	if _, err := os.Stat(policiesDir); os.IsNotExist(err) {
		log.Printf("Policies directory %s does not exist, creating...", policiesDir)
		if err := os.MkdirAll(policiesDir, 0755); err != nil {
			log.Fatalf("Failed to create policies directory: %v", err)
		}
	}

	// Create policy engine with FSM integration
	fmt.Printf("Creating policy engine with config path: %s\n", policiesDir)
	engine := policyd.NewPolicyEngine(policiesDir)

	// Load policies from directory
	fmt.Println("Loading policies from directory...")
	if err := engine.LoadPolicies(); err != nil {
		log.Fatalf("Failed to load policies: %v", err)
	}

	// Display loaded policies
	workerInfo := engine.GetWorkerInfo()
	fmt.Printf("Loaded %d policy workers:\n", engine.GetWorkerCount())
	for id, info := range workerInfo {
		fmt.Printf("  - %s: %s\n", id, info)
	}

	// Start policy file watcher for hot-reload
	fmt.Println("Starting policy file watcher...")
	engine.StartPolicyWatcher()

	// Start tracking some test PIDs
	testPIDs := []uint64{1234, 5678, 9999}
	for _, pid := range testPIDs {
		engine.TrackPid(pid)
		fmt.Printf("Tracking PID: %d\n", pid)
	}

	// Simulate some syscall events
	fmt.Println("\nSimulating syscall events...")

	// Create test events that should trigger policies
	events := []ipc.BpfSyscallEvent{
		{
			Ts:        uint64(time.Now().Unix()),
			Pid:       1234,
			SyscallNr: syscalls.SYS_OPENAT,
			Data:      createMockOpenatData("/etc/passwd"),
		},
		{
			Ts:        uint64(time.Now().Unix()),
			Pid:       1234,
			SyscallNr: syscalls.SYS_EXECVE,
			Data:      createMockExecveData("/bin/sh"),
		},
		{
			Ts:        uint64(time.Now().Unix()),
			Pid:       5678,
			SyscallNr: syscalls.SYS_WRITE,
			Data:      createMockWriteData("test content with root access"),
		},
		{
			Ts:        uint64(time.Now().Unix()),
			Pid:       9999,
			SyscallNr: syscalls.SYS_OPENAT,
			Data:      createMockOpenatData("/dev/input/event0"),
		},
		{
			Ts:        uint64(time.Now().Unix()),
			Pid:       1234,
			SyscallNr: syscalls.SYS_OPENAT,
			Data:      createMockOpenatData("/tmp/safe_file"),
		},
	}

	// Process events with delays to see execution progression
	for i, event := range events {
		fmt.Printf("\nProcessing event %d: ", i+1)
		printSyscallEvent(event)

		engine.HandleEvent(event)

		// Give workers time to process
		time.Sleep(100 * time.Millisecond)
	}

	// Set up graceful shutdown
	fmt.Println("\n\nPress Ctrl+C to shutdown...")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Run for a bit to show hot-reload capability
	go func() {
		time.Sleep(5 * time.Second)
		fmt.Println("\nTip: You can modify .policy files in the policies/ directory")
		fmt.Println("     Changes will be automatically detected and reloaded!")
	}()

	// Wait for shutdown signal
	<-c
	fmt.Println("\nShutting down policy engine...")
	engine.Shutdown()
	fmt.Println("Demo complete!")
}

func printSyscallEvent(event ipc.BpfSyscallEvent) {
	switch event.SyscallNr {
	case syscalls.SYS_OPENAT:
		// Extract pathname from data
		pathname := extractStringFromData(event.Data[:])
		fmt.Printf("openat(pathname=\"%s\") PID=%d", pathname, event.Pid)
	case syscalls.SYS_EXECVE:
		// Extract filename from data
		filename := extractStringFromData(event.Data[:])
		fmt.Printf("execve(filename=\"%s\") PID=%d", filename, event.Pid)
	case syscalls.SYS_WRITE:
		// Extract content from data (skip first 4 bytes which are length)
		content := extractStringFromData(event.Data[4:])
		fmt.Printf("write(content=\"%s\") PID=%d", content, event.Pid)
	default:
		fmt.Printf("syscall_%d PID=%d", event.SyscallNr, event.Pid)
	}
}

func extractStringFromData(data []uint8) string {
	// Find null terminator
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

func createMockOpenatData(pathname string) [260]uint8 {
	var data [260]uint8
	copy(data[:], []byte(pathname))
	return data
}

func createMockExecveData(filename string) [260]uint8 {
	var data [260]uint8
	copy(data[:], []byte(filename))
	return data
}

func createMockWriteData(content string) [260]uint8 {
	var data [260]uint8
	// First 4 bytes for length, then content
	length := uint32(len(content))
	data[0] = byte(length)
	data[1] = byte(length >> 8)
	data[2] = byte(length >> 16)
	data[3] = byte(length >> 24)
	copy(data[4:], []byte(content))
	return data
}
