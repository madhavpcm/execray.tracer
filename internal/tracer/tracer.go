package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"execray.tracer/pkg/syscalls"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
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

func TraceDaemon(log *logrus.Logger, pid uint32) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	tracerSpec, err := loadTracer()
	if err != nil {
		log.Fatalf("loading of eBPF object spec failed: %v", err)
	}
	log.Debugf("%v", tracerSpec.Variables["target_pid"])
	if err := tracerSpec.Variables["target_pid"].Set(uint32(pid)); err != nil {
		log.Fatalf("setting of eBPF object vars failed: %v", err)
	}
	var tracerObj tracerObjects
	if err := tracerSpec.LoadAndAssign(&tracerObj, nil); err != nil {
		log.Fatalf("error loading ebpf obj: %v", err)
	}

	// --- 3. Attach BPF Program ---
	// Attach to the raw_syscalls/sys_enter tracepoint.
	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", tracerObj.HandleSysEnter, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("Tracepoint attached. Waiting for events... Press Ctrl+C to exit.")

	// --- 4. Read from Ring Buffer ---
	// Open a ring buffer reader from the BPF map.
	rd, err := ringbuf.NewReader(tracerObj.Rb)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	var event bpfSyscallEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Info("Exiting...")
				return
			}
			log.Infof("reading from reader: %s", err)
			continue
		}

		// --- 5. Parse Data ---
		// The raw sample contains the data from our C struct. We can copy it
		// to our Go struct.
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Tracef("parsing ringbuf event: %s", err)
			continue
		}
		// The bpf2go command generates Go structs and functions to load the BPF object.
		// We can rewrite the value of "target_pid" in the BPF program before loading it.
		// Create a goroutine to handle signals and close the reader, which unblocks the loop.
		go func() {
			<-stopper
			log.Println("Received signal, stopping...")
			if err := rd.Close(); err != nil {
				log.Fatalf("closing ringbuf reader: %s", err)
			}
		}()

		// Print the structured data based on the syscall number.
		printSyscallEvent(&event, log)
	}

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
