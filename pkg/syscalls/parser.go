package syscalls

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	__NR_openat = 56
	__NR_write  = 64
	__NR_execve = 221
	DATA_LEN    = 256
)

type SyscallDataParser interface {
	// Parse reads from the byte reader and populates the struct.
	Parse(reader *bytes.Reader) error
	// String returns a formatted string representation of the event.
	String() string
}

// openatEvent holds the parsed data for an openat syscall.
type openatEvent struct {
	Pathname [DATA_LEN]byte
}

func (o *openatEvent) Parse(reader *bytes.Reader) error {
	return binary.Read(reader, binary.LittleEndian, o)
}
func (o *openatEvent) String() string {
	return fmt.Sprintf("openat, Path: %s", cString(o.Pathname[:]))
}

// execveEvent holds the parsed data for an execve syscall.
type execveEvent struct {
	Filename [DATA_LEN]byte
}

func (e *execveEvent) Parse(reader *bytes.Reader) error {
	return binary.Read(reader, binary.LittleEndian, e)
}
func (e *execveEvent) String() string {
	return fmt.Sprintf("execve, Filename: %s", cString(e.Filename[:]))
}

// writeEvent holds the parsed data for a write syscall.
type writeEvent struct {
	Len uint32
	Buf [DATA_LEN]byte
}

func (w *writeEvent) Parse(reader *bytes.Reader) error {
	return binary.Read(reader, binary.LittleEndian, w)
}
func (w *writeEvent) String() string {
	readLen := w.Len
	if readLen > DATA_LEN {
		readLen = DATA_LEN
	}
	content := string(w.Buf[:readLen])
	return fmt.Sprintf("write, Len: %d, Content: %q", w.Len, content)
}

var syscallParserMap = map[uint64]func() SyscallDataParser{
	__NR_openat: func() SyscallDataParser { return &openatEvent{} },
	__NR_execve: func() SyscallDataParser { return &execveEvent{} },
	__NR_write:  func() SyscallDataParser { return &writeEvent{} },
}

func SyscallParser(syscall uint64) (func() SyscallDataParser, error) {
	parser, ok := syscallParserMap[syscall]
	if ok {
		return parser, nil
	} else {
		return nil, fmt.Errorf("syscall [%v] not supported", syscall)
	}
}

// cString converts a null-terminated C string in a byte slice to a Go string.
func cString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}
