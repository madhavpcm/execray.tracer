package tracer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" tracer trace.bpf.c -- -I./headers
