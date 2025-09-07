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
}

func NewDaemon(pid int) (*Daemon, error) {
	d := &Daemon{}
	if err := d.initDaemon(pid); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Daemon) Serve() error {
	g, _ := errgroup.WithContext(context.Background())

	// socket server
	g.Go(func() error {
		//isolate socket server and tracer daemon into separate threads
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		return d.serveSocket("/var/run/execray.tracerd.sock")
	})

	// tracer daemon which listens for ebpf events
	g.Go(func() error {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		return d.tracerDaemon()
	})

	// Graceful exit
	g.Go(func() error {
		<-d.gracefulExit
		d.log.Println("Received signal, stopping...")
		return d.Close()
	})

	return g.Wait()
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

func (d *Daemon) serveSocket(socketPath string) error {
	_ = os.Remove(socketPath)

	for {
		conn, err := d.socketListener.Accept()
		if err != nil {
			continue
		}
		go d.handleConn(conn)
	}
}

func (d *Daemon) handleConn(conn net.Conn) {
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

	return errors.Join(errs...)
}

func (d *Daemon) initDaemon(pid int) error {
	// Exit handling
	d.gracefulExit = make(chan os.Signal, 1)
	signal.Notify(d.gracefulExit, os.Interrupt, syscall.SIGTERM)

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
	d.log.Debugf("%v", tracerSpec)
	d.log.Debugf("%v", tracerSpec.Variables["target_pid"])
	if err := tracerSpec.Variables["target_pid"].Set(uint32(pid)); err != nil {
		d.log.Errorf("%v", err)
		return fmt.Errorf("setting of eBPF object vars failed: %v", err)
	}
	var tracerObj tracerObjects
	if err := tracerSpec.LoadAndAssign(&tracerObj, nil); err != nil {
		d.log.Errorf("%v", err)
		return fmt.Errorf("error loading eBPF object: %v", err)
	}

	// Link Tracepoint
	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", tracerObj.HandleSysEnter, nil)
	if err != nil {
		d.log.Errorf("%v", err)
		return fmt.Errorf("error attaching tracepoint : %v", err)
	}
	d.tracePoint = tp

	d.log.Println("Tracepoint attached. Waiting for events... Press Ctrl+C to exit.")

	// Connect to shared ringbuffer
	buffer, err := ringbuf.NewReader(tracerObj.Rb)
	if err != nil {
		d.log.Errorf("%v", err)
		return fmt.Errorf("opening ring buffer: %v", err)
	}
	d.ringBuffer = buffer
	return nil
}

func (d *Daemon) tracerDaemon() error {
	var event bpfSyscallEvent
	for {
		record, err := d.ringBuffer.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				d.log.Info("Exiting...")
				return err
			}
			d.log.Infof("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			d.log.Tracef("parsing ringbuf event: %s", err)
			continue
		}

		printSyscallEvent(&event, d.log)
	}

}
