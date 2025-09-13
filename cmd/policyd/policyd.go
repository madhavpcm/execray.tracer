package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"execray.tracer/internal/policyd"
	"execray.tracer/pkg/ipc"
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

	// Determine config path - default to local policies directory
	configPath := os.Getenv("POLICY_CONFIG_PATH")
	if configPath == "" {
		configPath = "./policies"
	}
	log.WithField("configPath", configPath).Info("Using policy configuration directory")

	// Create and configure the policy engine with FSM-based policy loading
	engine := policyd.NewPolicyEngine(configPath)

	// Load policies from configuration directory
	if err := engine.LoadPolicies(); err != nil {
		log.WithError(err).Warn("Failed to load policies from config directory")
		log.Info("Continuing with empty policy set - policies can be added dynamically")
	} else {
		workerCount := engine.GetWorkerCount()
		log.WithField("workers", workerCount).Info("Policy loading completed")

		if workerCount > 0 {
			// Log information about loaded policies
			workerInfo := engine.GetWorkerInfo()
			for policyId, info := range workerInfo {
				log.WithFields(logrus.Fields{
					"policyId": policyId,
					"info":     info,
				}).Info("Policy worker active")
			}
		}
	}

	// Start policy file watcher for hot-reloading
	engine.StartPolicyWatcher()
	log.Info("Policy file watcher started for hot-reloading")

	// Set up dynamic PID tracking
	engine.TrackPid(10000) // Default PID for compatibility
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
