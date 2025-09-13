package syscalls

import (
	"bytes"
	"fmt"
)

const (
	SYS_OPENAT = 56
	SYS_WRITE  = 64
	SYS_EXECVE = 221
	DATA_LEN   = 256
)

type SyscallDataParser interface {
	Parse(reader *bytes.Reader) error
	String() string
}

var syscallParserMap = map[uint64]func() SyscallDataParser{
	SYS_OPENAT: func() SyscallDataParser { return &openatEvent{} },
	SYS_EXECVE: func() SyscallDataParser { return &execveEvent{} },
	SYS_WRITE:  func() SyscallDataParser { return &writeEvent{} },
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
