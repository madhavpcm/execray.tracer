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
	"syscall"
	"time"

	"execray.tracer/pkg/ipc"
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

	// channels
	return nil
}

type Daemon struct {
	log *logrus.Logger

	// daemon sync
	commandMutex sync.Mutex

	// daemon
	gracefulExit chan os.Signal
	tracePoint   link.Link

	// daemon cfg
	TracingEnabled bool

	// ebpf commands
	ebpfProgram tracerObjects
	ringBuffer  *ringbuf.Reader

	// IPC
	// Channel to send events from tracer to the single client handler.
	traceEventsChannel chan ipc.BpfSyscallEvent
	ebpfEventsChannel  chan []byte
	// Channel to parse tracerctl commands
	commandChannelRead  chan ipc.Command
	commandChannelWrite chan ipc.CommandResponse
}

func NewDaemon() (*Daemon, error) {
	d := &Daemon{
		// buffer of 1024 traces
		ebpfEventsChannel:   make(chan []byte, 256),
		commandChannelRead:  make(chan ipc.Command),
		commandChannelWrite: make(chan ipc.CommandResponse),
		traceEventsChannel:  make(chan ipc.BpfSyscallEvent, 256),
	}
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

	// tracer daemon which listens for ebpf events
	g.Go(func() error {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		return d.tracerDaemon(gCtx)
	})

	g.Go(func() error {
		return d.serveSocket(gCtx, ipc.SocketPathCommands)
	})

	g.Go(func() error {
		return d.processCommands(gCtx)
	})

	d.log.Println("Daemon started successfully. Press Ctrl+C to exit.")

	// Wait for all goroutines to finish.
	// If any goroutine returns an error, g.Wait() will return it.
	if err := g.Wait(); err != nil && err != context.Canceled {
		// We ignore context.Canceled because it's the expected error on shutdown.
		cancel()
		d.Close()
		return fmt.Errorf("daemon stopped with error: %w", err)
	}

	d.log.Println("Daemon shut down gracefully.")
	return nil
}

func (d *Daemon) serveSocket(ctx context.Context, socketPath string) error {
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

		// Handle the new connection in its own goroutine
		go d.handleSocketConnection(ctx, conn, errChan)
	}
}
func (d *Daemon) handleSocketConnection(ctx context.Context, conn net.Conn, errChan chan<- error) {

	// handle socket io in 2 r/w loops
	switch conn.LocalAddr().String() {
	case ipc.SocketPathTraces:
		go d.tracesSocketWriter(ctx, gob.NewEncoder(conn), errChan)
	case ipc.SocketPathCommands:
		go d.commandSocketWriter(ctx, gob.NewEncoder(conn), errChan)
		go d.commandSocketReader(ctx, gob.NewDecoder(conn), errChan)
	}

	d.log.Infof("New client connection established. %s", conn.LocalAddr().String())

	<-ctx.Done()
	d.log.Printf("socket connection handler: parent context canceled: %v", ctx.Err())
}

func (d *Daemon) commandSocketReader(ctx context.Context, decoder *gob.Decoder, errChan chan<- error) {
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

func (d *Daemon) commandSocketWriter(ctx context.Context, encoder *gob.Encoder, errChan chan<- error) {
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

func (d *Daemon) tracesSocketWriter(ctx context.Context, encoder *gob.Encoder, errChan chan<- error) {
	d.log.Info("Traces Socket writer started.")
	defer d.log.Info("Traces Socket writer stopped.")

	for {
		select {
		case <-ctx.Done():
			// Context was canceled.
			return

		case event, ok := <-d.traceEventsChannel:
			// check if trace channel was prematurely closed
			if !ok {
				d.log.Info("Trace channel closed. Exiting socket writer.")
			}

			if err := encoder.Encode(&event); err != nil {
				errChan <- fmt.Errorf("error encoding trace event: %w", err)
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
	if d.tracePoint != nil {
		if err := d.tracePoint.Close(); err != nil {
			errs = append(errs, fmt.Errorf("tracePoint: %w", err))
		}
	}

	close(d.commandChannelRead)
	close(d.commandChannelWrite)
	close(d.ebpfEventsChannel)
	close(d.traceEventsChannel)

	d.log.Debugf("%v", errors.Join(errs...))
	d.log.Infof("Closing tracerd daemon")

	return errors.Join(errs...)
}

func (d *Daemon) tracerDaemon(ctx context.Context) error {
	var wg sync.WaitGroup
	wg.Add(1)
	//Cleanup
	go func() {
		<-ctx.Done() // Block until the context is canceled.
		wg.Done()
		d.log.Info("Context canceled, closing tracer daemon...")
		if err := d.ringBuffer.Close(); err != nil {
			d.log.Errorf("failed to close ringbuf")
		}
	}()

	// ebpf event parser (consumer)
	go func() {
		defer wg.Done()
		var event ipc.BpfSyscallEvent

		// This loop will run until 'eventsChan' is closed and empty.
		for rawSample := range d.ebpfEventsChannel {
			d.log.Trace("ebpf consumer: got sample")
			if err := binary.Read(bytes.NewReader(rawSample), binary.LittleEndian, &event); err != nil {
				d.log.Tracef("Parsing ringbuf event: %s", err)
				continue
			}
			printSyscallEvent(&event, d.log)
		}
		d.log.Info("Event processor has finished.")
	}()

	d.log.Info("Tracer daemon started, waiting for eBPF events...")

	// ebpf event fetcher (producer)
	for {
		d.log.Info("ebpf producer: waiting for ringbuffer")
		record, err := d.ringBuffer.Read()
		if err != nil {
			// This error is expected on shutdown when the buffer is closed.
			if errors.Is(err, ringbuf.ErrClosed) {
				d.log.Info("Ring buffer closed, exiting daemon loop.")
				break
			}
			d.log.Infof("Reading from reader: %s", err)
			continue
		}

		d.log.Info("ebpf producer: producing ebpf event")
		select {
		case d.ebpfEventsChannel <- record.RawSample:
			// Event successfully queued.
		default:
			d.log.Warn("Event channel buffer is full. Dropping eBPF event.")
		}
	}

	wg.Wait()
	d.log.Info("Tracer daemon shut down gracefully.")

	return ctx.Err()
}

func (d *Daemon) processCommands(ctx context.Context) error {
	d.log.Info("Command Processor started, waiting for commands...")
	for {
		select {
		case <-ctx.Done():
			d.log.Info("Context canceled, stopping command processor...")
			return ctx.Err()
		case cmd := <-d.commandChannelRead:
			d.log.Infof("Processing command: %s", cmd.Type)

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
					err := d.ebpfProgram.tracerMaps.AllowedPids.Put(payload.Pid, true)
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

			case ipc.CmdGetPids:
				d.commandMutex.Lock()
				pids, err := d.fetchPidsFromEbpfMap()
				var response ipc.CommandResponse
				response.Type = ipc.CmdGetPids
				response.Payload = &ipc.PidListResponse{PIDs: pids, Error: fmt.Sprintf("%v", err)}
				d.log.Printf("Sending currently tracked pids: %v", pids)
				d.commandChannelWrite <- response
				d.commandMutex.Unlock()

			default:
				d.log.Printf("Unknown command type: %s", cmd.Type)
			}
		}
	}
}

func (d *Daemon) fetchPidsFromEbpfMap() ([]uint32, error) {
	pids := make([]uint32, 0)
	var key uint32
	var value byte

	iterator := d.ebpfProgram.tracerMaps.AllowedPids.Iterate()
	for iterator.Next(&key, &value) {
		pids = append(pids, key)
	}

	if err := iterator.Err(); err != nil {
		return nil, err
	}

	return pids, nil
}
