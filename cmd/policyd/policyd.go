// cmd/rule_engine/main.go
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"execray.tracer/internal/policyd"
	"execray.tracer/pkg/ipc"
)

func main() {
	// Initialize gob types
	ipc.Init()

	log.Println("Starting Policy Engine...")

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Create rule engine
	engine := policyd.NewPolicyEngine()

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
			engine.Broadcast(event)
		case sig := <-sigChan:
			log.Printf("Received signal %s, shutting down...", sig)
			return
		}
	}
}
