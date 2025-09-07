package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"

	"execray.tracer/pkg/ipc"
	"execray.tracer/pkg/syscalls"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

func (d *Daemon) initDaemon() error {
	// Exit handling
	d.gracefulExit = make(chan os.Signal, 1)
	signal.Notify(d.gracefulExit, os.Interrupt, syscall.SIGTERM)

	// Logger
	d.log = logrus.New()
	d.log.SetLevel(logrus.DebugLevel)

	// Initialize socket
	listener, err := net.Listen("unix", "/var/run/execray.tracerd.sock")
	if err != nil {
		return err
	}
	d.socketListener = listener

	// Initialize BPF object tracer
	tracerSpec, err := loadTracer()
	if err != nil {
		d.log.Errorf("%v", err)
		return fmt.Errorf("loading of eBPF object spec failed: %v", err)
	}
	d.log.Debugf("hi")
	d.log.Debugf("%v", tracerSpec.Variables["target_pid"])
	//if err := tracerSpec.Variables["target_pid"].Set(uint32(pid)); err != nil {
	//	d.log.Errorf("%v", err)
	//	return fmt.Errorf("setting of eBPF object vars failed: %v", err)
	//}
	if err := tracerSpec.LoadAndAssign(&d.ebpfProgram, nil); err != nil {
		d.log.Errorf("%v", err)
		return fmt.Errorf("error loading eBPF object: %v", err)
	}

	// Link Tracepoint
	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", d.ebpfProgram.HandleSysEnter, nil)
	if err != nil {
		d.log.Errorf("%v", err)
		return fmt.Errorf("error attaching tracepoint : %v", err)
	}
	d.tracePoint = tp

	d.log.Println("Tracepoint attached. Waiting for events... Press Ctrl+C to exit.")

	// Connect to shared ringbuffer
	buffer, err := ringbuf.NewReader(d.ebpfProgram.Rb)
	if err != nil {
		d.log.Errorf("%v", err)
		return fmt.Errorf("opening ring buffer: %v", err)
	}
	d.ringBuffer = buffer
	return nil
}

type Daemon struct {
	log *logrus.Logger

	// daemon sync
	commandMutex sync.Mutex

	// daemon
	gracefulExit   chan os.Signal
	socketListener net.Listener
	tracePoint     link.Link

	// daemon cfg
	TracingEnabled bool

	// ebpf commands
	ebpfProgram tracerObjects
	ringBuffer  *ringbuf.Reader

	// IPC
	// Atomically stores the active net.Conn to ensure only one client.
	activeConn atomic.Pointer[net.Conn]
	// Channel to send events from tracer to the single client handler.
	traceChannel chan ipc.BpfSyscallEvent
	// Channel to parse tracerctl commands
	commandChannel chan ipc.Command
}

func NewDaemon() (*Daemon, error) {
	d := &Daemon{}
	if err := d.initDaemon(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Daemon) Serve() error {
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

	// socket server
	g.Go(func() error {
		//isolate socket server and tracer daemon into separate threads
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		return d.serveSocket(gCtx, "/var/run/execray.tracerd.sock")
	})

	// tracer daemon which listens for ebpf events
	g.Go(func() error {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		return d.tracerDaemon(gCtx)
	})

	g.Go(func() error {
		return d.processCommands(gCtx)
	})

	d.log.Println("Daemon started successfully. Press Ctrl+C to exit.")

	// Wait for all goroutines to finish.
	// If any goroutine returns an error, g.Wait() will return it.
	if err := g.Wait(); err != nil && err != context.Canceled {
		// We ignore context.Canceled because it's the expected error on shutdown.
		return fmt.Errorf("daemon stopped with error: %w", err)
	}

	d.log.Println("Daemon shut down gracefully.")
	return nil
}

func printSyscallEvent(e *ipc.BpfSyscallEvent, log *logrus.Logger) {
	// Create a new parser instance for this event.
	dataReader := bytes.NewReader(e.Data[:])
	parserFactory, err := syscalls.SyscallParser(e.SyscallNr)
	if err != nil {
		log.Fatalf("failed to run: %v", err)
	}
	parser := parserFactory()
	log.Printf("PID: %d, Syscall: %d (untracked)", e.Pid, e.SyscallNr)

	// Parse the data from the union.
	if err := parser.Parse(dataReader); err != nil {
		log.Printf("PID: %d, Syscall: %d, Error parsing args: %v", e.Pid, e.SyscallNr, err)
		return
	}

	// Print the formatted string from the parser.
	log.Printf("PID: %d, Syscall: %s", e.Pid, parser.String())
}

func (d *Daemon) serveSocket(ctx context.Context, socketPath string) error {
	// Clean up any old socket file.
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

	// 1. Launch a goroutine to close the listener when the context is canceled.
	go func() {
		<-ctx.Done() // Block until context is canceled.
		d.log.Info("Context canceled, closing socket listener...")
		// Closing the listener will cause the Accept() call below to unblock.
		socketListener.Close()
	}()

	d.log.Info("Socket server listening on ", socketPath)
	for {
		conn, err := socketListener.Accept()
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

		// only ensure one client can send data
		if !d.activeConn.CompareAndSwap(nil, &conn) {
			d.log.Println("Rejecting new client; a client is already connected.")
			conn.Close()
			continue
		}

		// Handle the new connection in its own goroutine.
		go d.handleSocketConnection(ctx, conn)
	}
}

func (d *Daemon) handleSocketConnection(ctx context.Context, conn net.Conn) {
	// ... setup and defer logic remains the same ...

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Pass the gob Encoder/Decoder to the loops.
	go d.readLoop(connCtx, cancel, gob.NewDecoder(conn))
	go d.writeLoop(connCtx, cancel, gob.NewEncoder(conn))

	<-connCtx.Done()
}

func (d *Daemon) readLoop(ctx context.Context, cancel context.CancelFunc, decoder *gob.Decoder) {
	defer cancel()
	for {
		var cmd ipc.Command // Decode directly into the specific command type.
		if err := decoder.Decode(&cmd); err != nil {
			d.log.Printf("Error decoding command from client: %v", err)
			return
		}
		// Send the command to the central processor.
		d.commandChannel <- cmd
	}
}

// writeLoop reads from the dedicated event channel.
func (d *Daemon) writeLoop(ctx context.Context, cancel context.CancelFunc, encoder *gob.Encoder) {
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-d.traceChannel: // Receives a bpfSyscallEvent
			if err := encoder.Encode(&event); err != nil {
				d.log.Printf("Error encoding event to client: %v", err)
				return
			}
		}
	}
}

func (d *Daemon) Close() error {
	var errs []error

	if d.ringBuffer != nil {
		if err := d.ringBuffer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("ringBuffer: %w", err))
		}
	}
	if d.socketListener != nil {
		if err := d.socketListener.Close(); err != nil {
			errs = append(errs, fmt.Errorf("socketListener: %w", err))
		}
	}
	if d.tracePoint != nil {
		if err := d.tracePoint.Close(); err != nil {
			errs = append(errs, fmt.Errorf("tracePoint: %w", err))
		}
	}
	d.log.Debugf("%v", errors.Join(errs...))

	return errors.Join(errs...)
}

func (d *Daemon) tracerDaemon(ctx context.Context) error {
	// 1. Launch a goroutine to close the ring buffer when the context is canceled.
	go func() {
		<-ctx.Done() // Block until the context is canceled.
		d.log.Info("Context canceled, closing ring buffer...")
		if err := d.ringBuffer.Close(); err != nil {
			d.log.Errorf("Error closing ring buffer: %v", err)
		}
	}()

	d.log.Info("Tracer daemon started, waiting for eBPF events...")
	var event ipc.BpfSyscallEvent
	for {
		record, err := d.ringBuffer.Read()
		if err != nil {
			// 2. The Read() call will return ringbuf.ErrClosed after d.ringBuffer.Close() is called.
			if errors.Is(err, ringbuf.ErrClosed) {
				d.log.Info("Ring buffer closed, exiting daemon loop.")
				// Return ctx.Err() to signal that shutdown was due to cancellation.
				return ctx.Err()
			}
			d.log.Infof("Reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			d.log.Tracef("Parsing ringbuf event: %s", err)
			continue
		}

		printSyscallEvent(&event, d.log)
	}
}

func (d *Daemon) processCommands(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case cmd := <-d.commandChannel:
			d.log.Printf("Processing command: %s", cmd.Type)

			switch cmd.Type {
			case ipc.CmdSetTracingStatus:
				// Type-assert the payload to the correct struct.
				if payload, ok := cmd.Payload.(ipc.SetTracingStatusPayload); ok {
					d.commandMutex.Lock()
					d.TracingEnabled = payload.Enabled
					d.commandMutex.Unlock()
					d.log.Printf("Tracing enabled status set to: %v", payload.Enabled)
				} else {
					d.log.Printf("Invalid payload for %s", cmd.Type)
				}

			case ipc.CmdAddPid:
				if payload, ok := cmd.Payload.(ipc.PidPayload); ok {
					d.commandMutex.Lock()
					//FIXME validate if this PID exists in userspace
					err := d.ebpfProgram.tracerMaps.AllowedPids.Put(payload.Pid, struct{}{})
					if err != nil {
						d.log.Printf("Failed to sync (add) PID %d to eBPF map: %v", payload.Pid, err)
						continue
					}
					d.commandMutex.Unlock()
					d.log.Printf("Added PID to trace list: %d", payload.Pid)
				} else {
					d.log.Printf("Invalid payload for %s", cmd.Type)
				}

			case ipc.CmdRemovePid:
				if payload, ok := cmd.Payload.(ipc.PidPayload); ok {
					d.commandMutex.Lock()
					err := d.ebpfProgram.tracerMaps.AllowedPids.Delete(payload.Pid)
					if err != nil {
						d.log.Printf("Failed to sync (remove) PID %d from eBPF map: %v", payload.Pid, err)
						continue
					}
					d.commandMutex.Unlock()
					d.log.Printf("Removed PID from trace list: %d", payload.Pid)
				} else {
					d.log.Printf("Invalid payload for %s", cmd.Type)
				}

			default:
				d.log.Printf("Unknown command type: %s", cmd.Type)
			}
		}
	}
}
