package syscalls

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type openatEvent struct {
	Pathname [DATA_LEN]byte
}

func (o *openatEvent) Parse(reader *bytes.Reader) error {
	return binary.Read(reader, binary.LittleEndian, o)
}
func (o *openatEvent) String() string {
	return fmt.Sprintf("openat, Path: %s", cString(o.Pathname[:]))
}
