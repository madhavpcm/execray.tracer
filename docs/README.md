# execray.tracer

This repo is used to host an ebpf syscall tracer as part of execRay (Malicious Codepath Execution Detection). At the moment this only works with `aarch64` machines.

## Build

### Fetch Linux headers
`sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./internal/tracer/vmlinux.h`

### Build
```sh

go generate ./internal/tracer
go build

```

### Run

```
./execray.tracer <pid>
```
