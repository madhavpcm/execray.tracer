package policyd

import (
	"fmt"
	"sync"
	"context"
	"encoding/gob"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"execray.tracer/pkg/ipc"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// PolicyEngine is the central daemon that oversees all policies and workers.
type PolicyEngine struct {
	loader     *PolicyLoader
	ConfigPath string
	Workers  map[uint64]*PolicyEngineWorker
	Pids     sync.Map
	workerMu sync.RWMutex
	log      *logrus.Logger
	// syscall events come here from socket
	traceEventsChannel chan ipc.BpfSyscallEvent
	// Channel to parse tracerctl commands
	commandChannelRead  chan ipc.Command
	commandChannelWrite chan ipc.CommandResponse
}

func (d *PolicyEngine) Serve() error {
	ctx, cancel := context.WithCancel(context.Background())
	g, gCtx := errgroup.WithContext(ctx)
	defer cancel()

	g.Go(func() error {
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

		select {
		case sig := <-signalChan:
			d.log.Printf("Received signal: %s, shutting down...", sig)
			cancel() // Signal all other goroutines to stop.
			return nil
		case <-gCtx.Done():
			// The context was canceled by another part of the application.
			return gCtx.Err()
		}
	})

	g.Go(func() error {
		return d.serveSocket(gCtx, ipc.PolicydCommandsSocket)
	})
	g.Go(func() error {
		return d.serveSocket(gCtx, ipc.PolicydTracesSocket)
	})

	g.Go(func() error {
		return d.processCommands(gCtx)
	})
	// If any goroutine returns an error, g.Wait() will return it.
	if err := g.Wait(); err != nil && err != context.Canceled {
		// We ignore context.Canceled because it's the expected error on shutdown.
		cancel()
		return fmt.Errorf("daemon stopped with error: %w", err)
	}

	return nil
}

func (d *PolicyEngine) Close() error {
	var errs []error

	close(d.commandChannelRead)
	close(d.commandChannelWrite)
	close(d.traceEventsChannel)

	d.log.Debugf("%v", errors.Join(errs...))
	d.log.Infof("Closing tracerd daemon")

	return errors.Join(errs...)
}

func (d *PolicyEngine) processCommands(ctx context.Context) error {
	d.log.Info("Command Processor started, waiting for commands...")
	for {
		select {
		case <-ctx.Done():
			d.log.Info("Context canceled, stopping command processor...")
			return ctx.Err()
		case cmd := <-d.commandChannelRead:
			d.log.Infof("Processing command: %s", cmd.Type)

			switch cmd.Type {

			case ipc.CmdAddPid:
				if payload, ok := cmd.Payload.(ipc.PidPayload); ok {
					d.TrackPid(uint64(payload.Pid))
					d.log.Printf("Added PID to trace list: %d", payload.Pid)
				} else {
					d.log.Printf("Invalid payload for %s", cmd.Type)
				}

			case ipc.CmdRemovePid:
				if payload, ok := cmd.Payload.(ipc.PidPayload); ok {
					d.UntrackPid(uint64(payload.Pid))
					d.log.Printf("Removed PID from trace list: %d", payload.Pid)
				} else {
					d.log.Printf("Invalid payload for %s", cmd.Type)
				}

			case ipc.CmdGetPids:
				pids := d.fetchPidsFromMap()
				d.log.Printf("Sending currently tracked pids: %v", pids)

			default:
				d.log.Printf("Unknown command type: %s", cmd.Type)
			}
		}
	}
}

func (d *PolicyEngine) serveSocket(ctx context.Context, socketPath string) error {
	// Clean up any old socket file.
	errChan := make(chan error, 2) // Buffer for 2 (one for read, one for write)
	if err := os.RemoveAll(socketPath); err != nil {
		d.log.Errorf("Failed to remove old socket file: %v", err)
		return err
	}
	// Defer cleanup for when this function exits.
	defer os.RemoveAll(socketPath)

	// Create a listener. The net.ListenConfig struct respects the context
	// for the listen operation itself, but we still need to handle Accept().
	lc := net.ListenConfig{}
	socketListener, err := lc.Listen(ctx, "unix", socketPath)
	if err != nil {
		d.log.Errorf("Failed to listen on socket: %v", err)
		return err
	}

	go func() {
		<-ctx.Done()
		d.log.Info("Context canceled, closing socket listener...")
		socketListener.Close()
		close(errChan)
	}()

	d.log.Info("Socket server listening on ", socketPath)
	// Each socket connnection is handled parallely via goroutines
	for {
		d.log.Debugf("accepting for connections")
		conn, err := socketListener.Accept()
		d.log.Debugf("accepted for connections")
		// handle accept after close
		if err != nil {
			select {
			case <-ctx.Done():
				d.log.Info("Socket listener shut down gracefully.")
				return ctx.Err() // Returns context.Canceled
			default:
				d.log.Errorf("Socket accept error: %v", err)
				return err
			}
		}

		// Handle the new connection in own goroutine
		go d.handleSocketConnection(ctx, conn, errChan)
	}
}
func (d *PolicyEngine) handleSocketConnection(ctx context.Context, conn net.Conn, errChan chan<- error) {

	d.log.Debug("handle sock routine")
	// handle socket io in 2 r/w loops
	if conn.LocalAddr().String() == ipc.PolicydCommandsSocket {
		d.log.Debug("commands sock routine")
		go d.commandSocketWriter(ctx, gob.NewEncoder(conn), errChan)
		go d.commandSocketReader(ctx, gob.NewDecoder(conn), errChan)
	} else if conn.LocalAddr().String() == ipc.PolicydTracesSocket {
		d.log.Debug("traces sock routine")
		go d.tracesSocketReader(ctx, gob.NewDecoder(conn), errChan)
	}

	d.log.Infof("New client connection established. %s", conn.LocalAddr().String())
	<-ctx.Done()
	d.log.Printf("socket connection handler: parent context canceled: %v", ctx.Err())
}

func (d *PolicyEngine) commandSocketReader(ctx context.Context, decoder *gob.Decoder, errChan chan<- error) {
	for {
		var msg ipc.Message
		// ensure conn is owned by handleSocketConnection
		if conn, ok := ctx.Value("conn").(net.Conn); ok {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		}

		err := decoder.Decode(&msg)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				select {
				case <-ctx.Done():
					// Context was canceled during the read, which is a clean exit.
					return
				default:
					continue
				}
			}
			// A real error (like io.EOF) occurred. Report it and exit.
			errChan <- fmt.Errorf("error decoding message: %w", err)
			return
		}

		// Use a select to avoid blocking if the command channel is full or the context is canceled.
		select {
		case d.commandChannelRead <- *msg.Command:
			d.log.Printf("Received command: %v", msg.Command)
		case <-ctx.Done():
			d.log.Printf("Context canceled during command send: %v", ctx.Err())
			return
		}
	}
}

func (d *PolicyEngine) commandSocketWriter(ctx context.Context, encoder *gob.Encoder, errChan chan<- error) {
	for {
		select {
		case <-ctx.Done():
			// Parent handler canceled the context. Clean exit.
			return

		case cmdResponse := <-d.commandChannelWrite:
			msg := ipc.Message{CommandResponse: &cmdResponse}
			d.log.Printf("Sending command response: %v", msg)
			if err := encoder.Encode(&msg); err != nil {
				errChan <- fmt.Errorf("error encoding command response: %w", err)
				return
			}
		}
	}
}
func (d *PolicyEngine) Init() {
	d.log.SetLevel(logrus.DebugLevel)
}
func (d *PolicyEngine) tracesSocketReader(ctx context.Context, decoder *gob.Decoder, errChan chan<- error) {
	for {
		var event ipc.BpfSyscallEvent
		// ensure conn is owned by handleSocketConnection
		if conn, ok := ctx.Value("conn").(net.Conn); ok {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		}

		err := decoder.Decode(&event)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				select {
				case <-ctx.Done():
					// Context was canceled during the read, which is a clean exit.
					return
				default:
					continue
				}
			}
			// A real error (like io.EOF) occurred. Report it and exit.
			errChan <- fmt.Errorf("error decoding message: %w", err)
			return
		}

		d.HandleEvent(event)
	}
}

// NewPolicyEngine creates and initializes the main policy engine.
func NewPolicyEngine() *PolicyEngine {
	engine := &PolicyEngine{
		Workers:             make(map[uint64]*PolicyEngineWorker),
		log:                 logrus.New(),
		commandChannelRead:  make(chan ipc.Command),
		commandChannelWrite: make(chan ipc.CommandResponse),
		traceEventsChannel:  make(chan ipc.BpfSyscallEvent, 256),
    Workers:    make(map[string]*PolicyEngineWorker),
		log:        logrus.New(),
		ConfigPath: configPath,
	}
  if configPath != "" {
		engine.loader = NewPolicyLoader(configPath)
	}
	// Initialize policy loader if config path is provided


	return engine
}

// LoadPolicies loads all policies from the config path and creates workers
func (pe *PolicyEngine) LoadPolicies() error {
	if pe.loader == nil {
		pe.log.Warn("No policy loader configured, skipping policy loading")
		return nil
	}

	// Load policies from files
	if err := pe.loader.LoadPolicies(); err != nil {
		return err
	}

	// Clear existing workers
	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()

	// Stop existing workers
	for _, worker := range pe.Workers {
		worker.Stop()
	}
	pe.Workers = make(map[string]*PolicyEngineWorker)

	// Create workers for loaded policies
	policies := pe.loader.GetPolicies()
	for id, policy := range policies {
		worker := NewPolicyEngineWorker(id, policy)
		pe.Workers[id] = worker
		worker.Start()

		pe.log.WithFields(logrus.Fields{
			"policyId": id,
			"states":   len(policy.FSM.States),
		}).Info("Policy worker started")
	}

	return nil
}

// StartPolicyWatcher starts the policy file watcher for hot-reloading
func (pe *PolicyEngine) StartPolicyWatcher() {
	if pe.loader == nil {
		return
	}

	pe.loader.StartWatcher()

	// Start a goroutine to periodically refresh workers when policies change
	go func() {
		ticker := time.NewTicker(10 * time.Second) // Check for worker refresh every 10 seconds
		defer ticker.Stop()

		for range ticker.C {
			if err := pe.RefreshPolicies(); err != nil {
				pe.log.WithError(err).Error("Failed to refresh policies")
			}
		}
	}()
}

// RefreshPolicies checks for policy changes and updates workers accordingly
func (pe *PolicyEngine) RefreshPolicies() error {
	if pe.loader == nil {
		return nil
	}

	policies := pe.loader.GetPolicies()

	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()

	// Check for new or updated policies
	for id, policy := range policies {
		if existingWorker, exists := pe.Workers[id]; exists {
			// Check if policy has been updated (simple check by comparing FSM state count)
			if len(existingWorker.CompiledPolicy.FSM.States) != len(policy.FSM.States) {
				pe.log.WithField("policyId", id).Info("Policy updated, restarting worker")
				existingWorker.Stop()
				newWorker := NewPolicyEngineWorker(id, policy)
				pe.Workers[id] = newWorker
				newWorker.Start()
			}
		} else {
			// New policy
			pe.log.WithField("policyId", id).Info("New policy detected, starting worker")
			worker := NewPolicyEngineWorker(id, policy)
			pe.Workers[id] = worker
			worker.Start()
		}
	}

	// Check for removed policies
	for id, worker := range pe.Workers {
		if _, exists := policies[id]; !exists {
			pe.log.WithField("policyId", id).Info("Policy removed, stopping worker")
			worker.Stop()
			delete(pe.Workers, id)
		}
	}

	return nil
}

// RegisterPolicy creates a new worker, adds it, and starts its goroutine.
// This method is kept for backward compatibility but enhanced for FSM support
func (pe *PolicyEngine) RegisterPolicy(policyId string, compiledPolicy *CompiledPolicy) {
	worker := NewPolicyEngineWorker(policyId, compiledPolicy)

	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()
	pe.Workers[policyId] = worker
	worker.Start()
}

// UnregisterPolicy stops a worker's goroutine and removes it from the engine.
func (pe *PolicyEngine) UnregisterPolicy(policyId string) {
	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()
	if worker, exists := pe.Workers[policyId]; exists {
		worker.Stop()
		delete(pe.Workers, policyId)
		pe.log.WithField("policyId", policyId).Info("Unregistered and stopped policy worker.")
	}
}

// GetWorkerInfo returns information about loaded workers
func (pe *PolicyEngine) GetWorkerInfo() map[string]string {
	pe.workerMu.RLock()
	defer pe.workerMu.RUnlock()

	info := make(map[string]string)
	for id, worker := range pe.Workers {
		if worker.CompiledPolicy != nil {
			info[id] = fmt.Sprintf("%d FSM states from %s",
				len(worker.CompiledPolicy.FSM.States),
				worker.CompiledPolicy.SourceFile,
			)
		} else {
			info[id] = "legacy policy"
		}
	}
	return info
}

// GetWorkerCount returns the number of active workers
func (pe *PolicyEngine) GetWorkerCount() int {
	pe.workerMu.RLock()
	defer pe.workerMu.RUnlock()
	return len(pe.Workers)
}

// Broadcast sends the event to all registered workers via their channels.
func (pe *PolicyEngine) Broadcast(event ipc.BpfSyscallEvent) {
	pe.workerMu.RLock()
	defer pe.workerMu.RUnlock()
	for _, worker := range pe.Workers {
		// Use a non-blocking send to prevent a slow worker from blocking the engine.
		select {
		case worker.eventChan <- event:
			// Event sent successfully.
		default:
			// The worker's channel buffer is full, so we drop the event for this worker.
			pe.log.WithField("policyId", worker.PolicyId).Warn("Worker channel full. Dropping event.")
		}
	}
}

// HandleEvent is the main entry point for incoming syscall events.
func (pe *PolicyEngine) HandleEvent(event ipc.BpfSyscallEvent) {
	if _, isTracked := pe.Pids.Load(event.Pid); isTracked {
		pe.Broadcast(event)
	}
}

// TrackPid adds a PID to the master list of monitored processes.
func (pe *PolicyEngine) TrackPid(pid uint64) {
	pe.Pids.Store(pid, true)
	pe.log.WithField("pid", pid).Info("Started tracking new PID.")
}

// UntrackPid removes a PID from the master list.
func (pe *PolicyEngine) UntrackPid(pid uint64) {
	pe.Pids.Delete(pid)
	pe.log.WithField("pid", pid).Info("Stopped tracking new PID.")
}

// Shutdown gracefully stops all running worker goroutines.
func (pe *PolicyEngine) Shutdown() {
	pe.workerMu.Lock()
	defer pe.workerMu.Unlock()
	pe.log.Info("Shutting down all policy workers...")
	for _, worker := range pe.Workers {
		worker.Stop()
	}
}

func (pe *PolicyEngine) fetchPidsFromMap() []uint64 {
	var collectedPids []uint64
	pe.Pids.Range(func(key, value any) bool {
		if pid, ok := key.(uint64); ok {
			collectedPids = append(collectedPids, pid)
		}
		return true
	})
	return collectedPids
}
