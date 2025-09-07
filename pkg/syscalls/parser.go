package syscalls

import (
	"bytes"
	"fmt"
)

const (
	__NR_openat = 56
	__NR_write  = 64
	__NR_execve = 221
	DATA_LEN    = 256
)

type SyscallDataParser interface {
	Parse(reader *bytes.Reader) error
	String() string
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
