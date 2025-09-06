package syscalls

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type execveEvent struct {
	Filename [DATA_LEN]byte
}

func (e *execveEvent) Parse(reader *bytes.Reader) error {
	return binary.Read(reader, binary.LittleEndian, e)
}
func (e *execveEvent) String() string {
	return fmt.Sprintf("execve, Filename: %s", cString(e.Filename[:]))
}
