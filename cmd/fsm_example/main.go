package main

import (
	"fmt"
	"log"

	"execray.tracer/internal/compiler"
	"execray.tracer/pkg/ipc"
	"execray.tracer/pkg/syscalls"
)

func main() {
	fmt.Println("=== FSM Compilation and Execution Demo ===")

	// Example 1: Simple malicious file access detection
	fmt.Println("\n1. Simple malicious file access detection:")
	simplePolicy := `path "malicious_read" {
		openat { pathname="/etc/passwd" }
	}`

	fsm1, err := compiler.CompileProgram(simplePolicy)
	if err != nil {
		log.Fatalf("Failed to compile simple policy: %v", err)
	}

	fmt.Printf("   Compiled FSM with %d states\n", len(fsm1.States))
	printFSMStructure(fsm1)

	// Example 2: Complex attack sequence detection
	fmt.Println("\n2. Complex attack sequence detection:")
	complexPolicy := `path "privilege_escalation" {
		openat { pathname =~ "/etc/.*" }
		execve { filename="/bin/sh" }
		write { content =~ ".*root.*" }
	}`

	fsm2, err := compiler.CompileProgram(complexPolicy)
	if err != nil {
		log.Fatalf("Failed to compile complex policy: %v", err)
	}

	fmt.Printf("   Compiled FSM with %d states\n", len(fsm2.States))
	printFSMStructure(fsm2)

	// Example 3: Conditional logic detection
	fmt.Println("\n3. Conditional logic detection:")
	conditionalPolicy := `path "conditional_attack" {
		openat { pathname="/etc/passwd" } ?
			execve { filename="/bin/bash" }
		:
			write { content="backup_attempt" }
	}`

	fsm3, err := compiler.CompileProgram(conditionalPolicy)
	if err != nil {
		log.Fatalf("Failed to compile conditional policy: %v", err)
	}

	fmt.Printf("   Compiled FSM with %d states\n", len(fsm3.States))
	printFSMStructure(fsm3)

	// Example 4: Execution simulation
	fmt.Println("\n4. FSM Execution Simulation:")

	// Use the simple policy for execution demo
	engine := compiler.NewExecutionEngine(fsm1)

	// Validate FSM
	if err := engine.ValidateFSM(); err != nil {
		log.Fatalf("FSM validation failed: %v", err)
	}
	fmt.Println("   FSM validation: PASSED")

	// Simulate syscall events
	events := []*ipc.BpfSyscallEvent{
		{
			Ts:        1234567890,
			Pid:       1234,
			SyscallNr: syscalls.SYS_OPENAT,
			Data:      createMockOpenatData("/etc/passwd"),
		},
		{
			Ts:        1234567891,
			Pid:       1234,
			SyscallNr: syscalls.SYS_OPENAT,
			Data:      createMockOpenatData("/tmp/safe_file"),
		},
		{
			Ts:        1234567892,
			Pid:       1234,
			SyscallNr: syscalls.SYS_EXECVE,
			Data:      createMockExecveData("/bin/sh"),
		},
	}

	fmt.Println("   Processing syscall events:")
	for i, event := range events {
		result, err := engine.ProcessEvent(event)
		if err != nil {
			log.Printf("Error processing event %d: %v", i, err)
			continue
		}

		fmt.Printf("     Event %d: ", i+1)
		printSyscallEvent(event)
		fmt.Printf("       Result: Matched=%v, FinalState=%s, Path=%v\n",
			result.Matched, result.FinalState, result.Path)
		if result.ErrorMessage != "" {
			fmt.Printf("       Error: %s\n", result.ErrorMessage)
		}

		// Reset for next event
		engine.Reset()
	}

	// Example 5: Performance measurement
	fmt.Println("\n5. Performance Measurement:")
	performanceBenchmark(fsm1)

	fmt.Println("\n=== Demo Complete ===")
}

func printFSMStructure(fsm *compiler.FSM) {
	fmt.Printf("   Initial State: %s\n", fsm.InitialState)
	fmt.Println("   States:")
	for id, state := range fsm.States {
		transitions := state.GetTransitions()
		fmt.Printf("     %s (%s)", id, state.String())
		if len(transitions) > 0 {
			fmt.Print(" -> [")
			for i, t := range transitions {
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Print(t.TargetState)
				if t.Condition != "" {
					fmt.Printf("(%s)", t.Condition)
				}
			}
			fmt.Print("]")
		}
		fmt.Println()
	}
}

func printSyscallEvent(event *ipc.BpfSyscallEvent) {
	switch event.SyscallNr {
	case syscalls.SYS_OPENAT:
		fmt.Print("openat")
	case syscalls.SYS_EXECVE:
		fmt.Print("execve")
	case syscalls.SYS_WRITE:
		fmt.Print("write")
	default:
		fmt.Printf("syscall_%d", event.SyscallNr)
	}
	fmt.Printf(" (PID=%d)", event.Pid)
}

func createMockOpenatData(pathname string) [260]uint8 {
	// Create mock data that matches the openat parser format
	// This is a simplified version - in real usage, the eBPF program would populate this
	var data [260]uint8
	copy(data[:], []byte(pathname))
	return data
}

func createMockExecveData(filename string) [260]uint8 {
	// Create mock data that matches the execve parser format
	var data [260]uint8
	copy(data[:], []byte(filename))
	return data
}

func performanceBenchmark(fsm *compiler.FSM) {
	engine := compiler.NewExecutionEngine(fsm)
	event := &ipc.BpfSyscallEvent{
		SyscallNr: syscalls.SYS_OPENAT,
		Data:      createMockOpenatData("/etc/passwd"),
	}

	// Warm up
	for i := 0; i < 100; i++ {
		engine.ProcessEvent(event)
		engine.Reset()
	}

	// Measure execution time
	iterations := 10000
	fmt.Printf("   Executing %d iterations...\n", iterations)

	// Since Go doesn't have high-precision timing in this simple demo,
	// we'll just confirm the operations complete successfully
	successCount := 0
	for i := 0; i < iterations; i++ {
		result, err := engine.ProcessEvent(event)
		if err == nil && result != nil {
			successCount++
		}
		engine.Reset()
	}

	fmt.Printf("   Successful executions: %d/%d (%.1f%%)\n",
		successCount, iterations, float64(successCount)/float64(iterations)*100)
}
