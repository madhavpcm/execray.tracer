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

	// FIXME: Dynamically Track Pid
	engine.TrackPid(10000)
	// Connect to the tracer daemon's event stream.
	eventChan, conn, err := ipc.StreamEvents(ipc.SocketPathTraces)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Info("Successfully connected to tracer daemon. Waiting for events...")

	// Start a goroutine to process events.
	go func() {
		for {
			select {
			case event, ok := <-eventChan:
				if !ok {
					log.Warn("Event channel closed by sender.")
					return
				}
				// Track any new PID we haven't seen before.
				if _, exists := engine.Pids.Load(event.Pid); !exists {
					engine.TrackPid(event.Pid)
				}
				engine.HandleEvent(event)
			case <-ctx.Done():
				// The context was canceled, so stop processing.
				log.Info("Stopping event processing loop.")
				return
			}
		}
	}()

	// Wait here until the shutdown signal is received.
	<-ctx.Done()

	// Cleanly shut down the engine and its workers.
	log.Info("Shutdown signal received. Shutting down engine...")
	engine.Shutdown()

	return nil
}
