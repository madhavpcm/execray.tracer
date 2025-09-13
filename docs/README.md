# execray.tracer

This repo is used to host an ebpf syscall tracer as part of execRay (Malicious Codepath Execution Detection). At the moment this only works with `aarch64` machines.

<img width="1286" height="673" alt="image" src="https://github.com/user-attachments/assets/f3992c04-d84c-4bc3-8512-7532d8e853bb" />


## Build

### Prerquisites

Generate your linux headers in the `./internal/tracer` directory

`sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./internal/tracer/vmlinux.h`

### Build

```sh

go generate ./internal/tracer # generate bpf objects and embeds them in go binaries

go build ./cmd/tracerd
go build ./cmd/tracercli
go build ./cmd/policyd
go build ./cmd/policycli
# OR
make all



```

### Run

### policyd

Run this before Running tracerd, tracerd will connect as a client to policyd and push events to policyd so that it can consume

```bash
go build ./cmd/policyd/
./policyd
```

#### tracerd

```
sudo ./tracerd
```
This should start the tracing daemon, it listens to a command socket and sends to a tracer socket.
We need it to be either TCP/Unix sockets so that syscalls are delivered in order. 

tracerd is run as superuser as ebpf needs elevated privileges

```go

const TracerdCommandsSocket = "/var/run/tracerd.commands.sock"
```

#### tracercli/policycli

You can run `sudo ./tracercli` for CLI help and autocompletions.

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
sudo ./tracercli add pid 345 #adds pid to tracking list
sudo ./tracercli remove pid 345 # removes pid from tracking list
sudo ./tracercli get pids # gets tracking list
```

