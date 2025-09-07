# execray.tracer

This repo is used to host an ebpf syscall tracer as part of execRay (Malicious Codepath Execution Detection). At the moment this only works with `aarch64` machines.


At the moment only one PID is tracked and is set in the beginning

## Build

### Prerquisites

Generate your linux headers in the `./internal/tracer` directory

`sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./internal/tracer/vmlinux.h`

### Build

```sh

go generate ./internal/tracer # generate bpf objects and embeds them in go binaries

##FIXME may fail with some C build issue, in that case, temporarily move tracer.bpf.c somewhere else
go build ./cmd/tracerd # builds ./tracerd
go build ./cmd/tracercli #  builds ./tracercli

```

### Run

#### tracerd

```
sudo ./tracerd
```
This should start the daemon, it listens to a command socket and sends to a tracer socket.
We need it to be either TCP/Unix sockets so that syscalls are delivered in order.

```go
const SocketPathTraces = "/var/run/tracerd.traces.sock" // daemon spits traced syscalls here (NEED to TEST)

const SocketPathCommands = "/var/run/tracerd.commands.sock" // daemon can be controlled via this socket
```

#### tracercli

You can run `./tracercli` for CLI help and autocompletions.

```
Usage:
  ./tracercli [command]

Available Commands:
  add         Add a resource to be traced.
  completion  Generate the autocompletion script for the specified shell
  get         Stop tracing a resource.
  help        Help about any command
  remove      Stop tracing a resource.
```

TLDR 

```bash
./tracercli add pid 345 #adds pid to tracking list
./tracercli remove pid 345 # removes pid from tracking list
./tracercli get pids # gets tracking list
```