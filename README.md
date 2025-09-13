# ExeRay Tracer: Real-time Malicious Codepath Detection 🛡️

[![Go Tests](https://img.shields.io/badge/tests-123%2B%20passing-brightgreen)](#testing)
[![eBPF](https://img.shields.io/badge/eBPF-enabled-blue)](#ebpf-integration)
[![DSL](https://img.shields.io/badge/DSL-custom%20compiler-orange)](#dsl-language)
[![Hot Reload](https://img.shields.io/badge/policies-hot%20reload-red)](#policy-engine)

> ** Project**: A revolutionary cybersecurity tool that uses a custom domain-specific language (DSL) and eBPF integration to detect malicious execution patterns in real-time.

## Highlights

- **🔤 Custom DSL**: Purpose-built domain-specific language for defining security policies
- **⚡ Real-time Compilation**: Live DSL → AST → FSM transformation with hot-reload
- **🔍 eBPF Integration**: High-performance syscall capture using Linux kernel technology
- **🎯 Pattern Matching**: Advanced finite state machine execution for threat detection

## System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Policy Files  │    │  eBPF Syscalls   │    │ Threat Detection│
│   (.policy)     │    │                  │    │                 │
└─────────┬───────┘    └─────────┬────────┘    └─────────┬───────┘
          │                      │                       │
          ▼                      ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   DSL Compiler  │    │     tracerd      │    │   Policy Engine │
│ Lexer→Parser→AST│◄───┤  (eBPF daemon)   ├───►│   (FSM Exec)    │
└─────────┬───────┘    └──────────────────┘    └─────────┬───────┘
          │                                              │
          ▼                                              ▼
┌─────────────────┐                            ┌─────────────────┐
│ FSM Generation  │                            │ Alert/Response  │
│ State Machines  │                            │                 │
└─────────────────┘                            └─────────────────┘
```

**Data Flow:**
1. **Policy Creation** → Write security policies in custom DSL
2. **Real-time Compilation** → DSL compiled to finite state machines
3. **Syscall Capture** → eBPF captures system calls from running processes
4. **Pattern Matching** → FSM engines match syscall sequences against policies
5. **Threat Detection** → Malicious patterns trigger alerts and responses



## 🛠️ Quick Start

### Prerequisites
- **Go 1.19+** - For compilation and execution
- **Linux Kernel 5.8+** - For eBPF support  
- **Root privileges** - Required for eBPF syscall tracing

### Installation & Demo

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
make

# Copy policies
mkdir -p ./bin/policies
cp ./policies/<required_policy> ./bin/policies/

# Must be run before tracerd
./bin/policyd
sudo ./bin/tracerd

# Add pids to both tracing and policy evaluation daemon
policycli add pid <pid>
tracercli add pid <pid>

# Observe logs
```


## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | Detailed system design and component interaction |
| [DSL Guide](docs/DSL_GUIDE.md) | Complete language specification and examples |
| [eBPF Integration](docs/EBPF_INTEGRATION.md) | Syscall capture and kernel integration details |
| [Performance Analysis](docs/PERFORMANCE.md) | Benchmarks, metrics, and optimization details |
| [Setup Guide](docs/SETUP.md) | Detailed installation and configuration |
| [Innovation Overview](docs/INNOVATION.md) | Technical highlights and competitive advantages |


### Custom DSL Compiler Pipeline
```
Policy Source → Lexer → Parser → AST → Semantic Analysis → FSM Generation → Execution Engine
```

**Key Highlights:**
- **Hand-written recursive descent parser** with error recovery
- **Real-time AST-to-FSM compilation** with state optimization  
- **Hot-reload capability** without system restart
- **Comprehensive testing framework** (123+ test functions)

## 🔧 Demo Programs

| Program | Purpose | Command |
|---------|---------|---------|
| **policyd_demo** | Full system demonstration | `go run cmd/policyd_demo/main.go` |
| **lexer_example** | DSL tokenization demo | `go run cmd/lexer_example/main.go 'policy_code'` |
| **parser_example** | AST generation demo | `go run cmd/parser_example/main.go 'policy_code'` |
| **fsm_example** | State machine execution | `go run cmd/fsm_example/main.go` |
| **tracerd** | eBPF syscall tracer | `sudo go run cmd/tracerd/main.go` |
| **policyd** | Policy engine daemon | `go run cmd/policyd/main.go` |

## 

### vs. Traditional Security Tools
- **Dynamic Policies**: Hot-reload vs. static configuration files
- **Custom Language**: Purpose-built DSL vs. generic rule formats  
- **Real-time Compilation**: Live AST/FSM generation vs. pre-compiled rules
- **eBPF Integration**: Kernel-level capture vs. userspace monitoring
- **State Machine Logic**: Complex pattern matching vs. simple signature matching

### Technical Innovation Factors
1. **Compiler Engineering**: Complete toolchain with lexer, parser, AST, FSM
2. **Language Design**: Domain-specific syntax optimized for security patterns
3. **Systems Programming**: eBPF integration for high-performance monitoring
4. **Software Engineering**: Comprehensive testing and error handling
5. **Real-time Processing**: Hot-reload and dynamic policy updates

## Live Demonstration link:

# Future Roadmap
- Machine Learning Integration**: Anomaly detection with policy patterns
- Distributed Deployment**: Multi-host policy coordination
- Visualization Dashboard**: Real-time threat monitoring UI
- Cloud Integration**: Container and Kubernetes support
- Extended Syscall Support**: Beyond openat/execve/write
- Explore uretprobes so that return values from syscalls can also be tracked
- A sys call dump -> Policy + Optimizer
- Add directives to DSL to detect static hardware from Kernel instead of coding it in (Eg. /dev/input/some_input_device)

---
by gomodtidy
