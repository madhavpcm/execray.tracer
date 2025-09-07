package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"execray.tracer/pkg/ipc"
	"execray.tracer/pkg/syscalls"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type bpfSyscallEvent struct {
	Ts        uint64
	Pid       uint64 // Notice that in bpf struct is 32bit but we have to 64bit align in aarch64
	SyscallNr uint64
	Args      [6]uint64
	// The C union is represented as a byte array.
	// Its size is determined by the largest member of the union.
	Data [260]uint8 // For write_args_t (4 bytes for len + 256 for buf)
}

type Daemon struct {
	mutex          sync.Mutex
	pids           map[int]struct{}
	log            *logrus.Logger
	ringBuffer     *ringbuf.Reader
	gracefulExit   chan os.Signal
	socketListener net.Listener
	tracePoint     link.Link
	ebpfProgram    tracerObjects
}

func NewDaemon(pid int) (*Daemon, error) {
	d := &Daemon{}
	if err := d.initDaemon(pid); err != nil {
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

func printSyscallEvent(e *bpfSyscallEvent, log *logrus.Logger) {
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
	listener, err := lc.Listen(ctx, "unix", socketPath)
	if err != nil {
		d.log.Errorf("Failed to listen on socket: %v", err)
		return err
	}

	// 1. Launch a goroutine to close the listener when the context is canceled.
	go func() {
		<-ctx.Done() // Block until context is canceled.
		d.log.Info("Context canceled, closing socket listener...")
		// Closing the listener will cause the Accept() call below to unblock.
		listener.Close()
	}()

	d.log.Info("Socket server listening on ", socketPath)
	for {
		conn, err := listener.Accept()
		if err != nil {
			// 2. After listener.Close() is called, Accept() returns an error.
			// We check if the context is done to confirm this was a graceful shutdown.
			select {
			case <-ctx.Done():
				d.log.Info("Socket listener shut down gracefully.")
				return ctx.Err() // Returns context.Canceled
			default:
				// This is an unexpected error.
				d.log.Errorf("Socket accept error: %v", err)
				return err
			}
		}

		// Handle the new connection in its own goroutine.
		go d.handleSocketConnection(conn)
	}
}

func (d *Daemon) handleSocketConnection(conn net.Conn) {
	defer conn.Close()

	var cmd ipc.Command
	if err := json.NewDecoder(conn).Decode(&cmd); err != nil {
		return
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	switch cmd.Action {
	case "add":
		d.pids[cmd.PID] = struct{}{}
		conn.Write([]byte(fmt.Sprintf("added %d\n", cmd.PID)))
	case "remove":
		delete(d.pids, cmd.PID)
		conn.Write([]byte(fmt.Sprintf("removed %d\n", cmd.PID)))
	default:
		conn.Write([]byte("unknown command\n"))
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

func (d *Daemon) initDaemon(pid int) error {
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
	if err := tracerSpec.Variables["target_pid"].Set(uint32(pid)); err != nil {
		d.log.Errorf("%v", err)
		return fmt.Errorf("setting of eBPF object vars failed: %v", err)
	}
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
	var event bpfSyscallEvent
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
