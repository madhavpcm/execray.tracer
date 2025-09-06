# ebpf-syscall-tracer

This repo is used to host an ebpf syscall tracer as part of Malicious Codepath Execution Detection. At the moment this only works with `aarch64` machines.

## Build

### Fetch Linux headers
`sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
