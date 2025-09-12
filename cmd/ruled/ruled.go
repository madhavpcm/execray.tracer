// cmd/rule_engine/main.go
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"execray.tracer/pkg/ipc"
)

type Rule struct {
	ID          string
	Description string
	SyscallNr   uint64   // Match specific syscall number
	PidFilter   []uint64 // If empty, match all PIDs
	Action      string   // "log", "alert"
}

type RuleEngine struct {
	rules []Rule
	log   *log.Logger
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		log: log.New(os.Stdout, "[RULE_ENGINE] ", log.LstdFlags),
		rules: []Rule{
			{
				ID:          "R001",
				Description: "Detect execve syscalls",
				SyscallNr:   221, // execve syscall number on arm64
				Action:      "alert",
			},
			{
				ID:          "R002",
				Description: "Detect openat syscalls",
				SyscallNr:   56, // openat syscall number
				Action:      "log",
			},
			{
				ID:          "R003",
				Description: "Detect write syscalls",
				SyscallNr:   64, // write syscall number
				Action:      "log",
			},
		},
	}
}

func (re *RuleEngine) EvaluateEvent(event ipc.BpfSyscallEvent) {
	for _, rule := range re.rules {
		matched := true

		// Check syscall number
		if rule.SyscallNr != 0 && event.SyscallNr != rule.SyscallNr {
   continue
		}

		// Check PID filter if specified

			switch rule.Action {
			case "log":
				re.log.Printf("Rule %s triggered: PID=%d, Syscall=%d, Timestamp=%d",
					rule.ID, event.Pid, event.SyscallNr, event.Ts)
			case "alert":
				re.log.Printf("🚨 ALERT! Rule %s: %s (PID=%d, Syscall=%d)",
					rule.ID, rule.Description, event.Pid, event.SyscallNr)
			}
	}
}

func main() {
	// Initialize gob types
	ipc.Init()

	log.Println("Starting Rule Engine...")

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Create rule engine
	engine := NewRuleEngine()

	// Use the updated StreamEvents function
	eventChan, conn, err := ipc.StreamEvents(ipc.SocketPathTraces)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	log.Println("Successfully connected to tracer daemon. Processing events...")

	for {
		select {
		case event, ok := <-eventChan:
			if !ok {
				log.Println("Event channel closed")
				return
			}
			engine.EvaluateEvent(event)
		case sig := <-sigChan:
			log.Printf("Received signal %s, shutting down...", sig)
			return
		}
	}
}
