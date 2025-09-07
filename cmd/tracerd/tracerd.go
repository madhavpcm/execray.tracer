package main

import (
	"log"
	"os"
	"strconv"

	tracer "execray.tracer/internal/tracer"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
)

func main() {
	//FIXME: Set an ebpf map for list of processes controlled by CLI
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <pid>", os.Args[0])
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("Invalid PID: %v", err)
	}
	//boilerplate
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove rlimit memlock:", err)
	}
	log.Printf("Attaching to PID: %d", pid)
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	tracerDaemon, err := tracer.NewDaemon(pid)
	if err != nil {
		log.Fatal(err)
	}
	if err := tracerDaemon.Serve(); err != nil {
		log.Fatal(err)
	}
}
