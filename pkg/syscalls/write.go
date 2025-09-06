package syscalls

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

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
