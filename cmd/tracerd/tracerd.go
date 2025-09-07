package main

import (
	"log"

	tracer "execray.tracer/internal/tracer"
	"execray.tracer/pkg/ipc"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
)

func main() {
	// for gob encoding
	ipc.Init()
	// boilerplate
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove rlimit memlock:", err)
	}
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	tracerDaemon, err := tracer.NewDaemon()
	if err != nil {
		log.Fatal(err)
	}
	if err := tracerDaemon.Serve(); err != nil {
		log.Fatal(err)
	}
}
