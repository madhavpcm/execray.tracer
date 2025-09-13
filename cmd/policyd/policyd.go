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
	ipc.Init()
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

	configPath := os.Getenv("POLICY_CONFIG_PATH")
	if configPath == "" {
		configPath = "./policies"
	}
	// Create and configure the policy engine.

	log.WithField("configPath", configPath).Info("Using policy configuration directory")

	// Create and configure the policy engine with FSM-based policy loading
	engine := policyd.NewPolicyEngine(configPath)
	engine.Init()

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

	engine.Serve()
	<-ctx.Done()

	engine.Shutdown()

	return nil
}
