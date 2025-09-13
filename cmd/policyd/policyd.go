package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"execray.tracer/internal/policyd"
	"execray.tracer/pkg/ipc"
	"execray.tracer/pkg/syscalls"
	"github.com/sirupsen/logrus"
)

func main() {
	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	// Use signal.NotifyContext for a modern, clean way to handle graceful shutdowns.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, log); err != nil {
		log.Fatalf("policy engine failed: %v", err)
	}

	log.Info("Shutdown complete.")
}

func run(ctx context.Context, log *logrus.Logger) error {
	ipc.Init() // Initialize gob types for IPC.
	log.Info("Starting Policy Engine...")

	// Create and configure the policy engine.
	engine := policyd.NewPolicyEngine()
	engine.Init()

	// FIXME: Compiler should generate DAG nodes and return a root

	writePolicy := &policyd.Policy{
		SyscallNr:   syscalls.SYS_WRITE,
		Name:        "file-write",
		Description: "A file is being written to.",
		Action:      "log", // The final action to take.
		Next:        nil,   // This is the last step in the chain.
	}

	openThenWritePolicy := &policyd.Policy{
		SyscallNr:   syscalls.SYS_OPENAT,
		Name:        "file-open",
		Description: "A file is opened, check for subsequent write.",
		Next:        writePolicy, // Chain to the next policy node.
	}

	// Register the policy chain with the engine.
	engine.RegisterPolicy(1, openThenWritePolicy)
	log.Info("Sample policy 'open -> write' registered.")

	engine.Serve()

	// Cleanly shut down the engine and its workers.
	engine.Shutdown()

	return nil
}
