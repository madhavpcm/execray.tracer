package main

import (
	"execray.tracer/internal/cli"
	"execray.tracer/pkg/ipc"
)

// This is the main entry point for the CLI binary.
// It simply calls the Execute function from the Cobra command package
func main() {
	ipc.Init()
	cli.Init()
	cli.Execute()
}
