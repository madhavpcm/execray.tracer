# Setup Guide

## Quick Setup for Judges

### Prerequisites Check
```bash
# Verify system requirements
uname -r                    # Should be >= 5.8 for eBPF support
go version                  # Should be >= 1.19
id                         # Note user ID (root required for eBPF)

# Expected output:
# Linux 5.15.0+ 
# go version go1.19+ linux/amd64
# uid=0(root) gid=0(root) groups=0(root)
```

### 2-Minute Quick Demo
```bash
# 1. Clone and build (30 seconds)
git clone <repository-url>
cd execray.tracer
go mod tidy && go build ./...

# 2. Verify installation (15 seconds) 
go test ./internal/compiler -v | head -20
# Expected: Multiple PASS results

# 3. Run live demo (75 seconds)
go run cmd/policyd_demo/main.go
# Expected: Policy compilation messages and event monitoring

# That's it! System is working if you see policy compilation output.
```

## Detailed Installation

### System Requirements

#### Operating System
- **Linux Kernel**: 5.8+ (for full eBPF support)
- **Architecture**: x86_64, ARM64
- **Distribution**: Ubuntu 20.04+, CentOS 8+, Debian 11+, Arch Linux

#### Software Dependencies
```bash
# Required packages (Ubuntu/Debian)
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    git \
    wget

# Required packages (CentOS/RHEL)
sudo dnf install -y \
    gcc \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel \
    git \
    wget

# Go installation (if not present)
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
```

#### Privilege Requirements
```bash
# Check current privileges
id

# For eBPF functionality, you need:
# - Root access (sudo or uid=0)
# - Or CAP_BPF + CAP_SYS_ADMIN capabilities

# Grant capabilities (alternative to root)
sudo setcap cap_bpf,cap_sys_admin+ep /usr/local/go/bin/go
```

### Installation Steps

#### 1. Clone Repository
```bash
# Clone the project
git clone <repository-url>
cd execray.tracer

# Verify repository structure
ls -la
# Expected: cmd/, internal/, pkg/, policies/, docs/, etc.
```

#### 2. Dependency Management
```bash
# Initialize Go modules
go mod tidy

# Verify dependencies
go mod verify
# Expected: "all modules verified"

# Check for any missing dependencies
go mod download
```

#### 3. Compilation
```bash
# Build all components
go build ./...

# Build specific demos
go build -o bin/policyd_demo cmd/policyd_demo/main.go
go build -o bin/lexer_example cmd/lexer_example/main.go
go build -o bin/parser_example cmd/parser_example/main.go
go build -o bin/fsm_example cmd/fsm_example/main.go

# Verify builds
ls -la bin/
# Expected: Multiple executable files
```

#### 4. eBPF Program Compilation (Optional)
```bash
# Compile eBPF program (if modifying eBPF code)
cd tracer/
clang -O2 -target bpf -c trace.bpf.c -o trace.bpf.o

# Verify eBPF object
file trace.bpf.o
# Expected: "trace.bpf.o: ELF 64-bit LSB relocatable, eBPF, version 1"
```

### Validation & Testing

#### 1. Unit Tests
```bash
# Run comprehensive test suite
go test ./... -v

# Expected output sample:
# === RUN   TestLexerBasic
# --- PASS: TestLexerBasic (0.00s)
# === RUN   TestParserSimple  
# --- PASS: TestParserSimple (0.00s)
# ...
# PASS
# ok      github.com/execray/tracer/internal/compiler    2.456s

# Run with coverage
go test ./... -cover
# Expected: coverage > 80% for all packages
```

#### 2. Component Tests
```bash
# Test lexer
go run cmd/lexer_example/main.go 'path "test" { openat { pathname =~ "/tmp" } }'
# Expected: Token stream output

# Test parser  
go run cmd/parser_example/main.go 'path "test" { execve { filename =~ "/bin/sh" } }'
# Expected: AST structure output

# Test FSM generation
go run cmd/fsm_example/main.go
# Expected: FSM state diagram and execution trace
```

#### 3. Integration Tests
```bash
# Test policy engine with minimal setup
go run cmd/policyd_demo/main.go &
PID=$!

# Wait for startup
sleep 2

# Check if policies loaded
ps aux | grep policyd_demo
# Expected: Running process

# Clean up
kill $PID
```

### Configuration

#### 1. Basic Configuration
```yaml
# Create config file: config/config.yaml
server:
  port: 8080
  host: "0.0.0.0"

policies:
  directory: "./policies"
  hot_reload: true
  max_policies: 100

performance:
  worker_pool_size: 8
  event_queue_size: 10000
  ring_buffer_size: 256KB

logging:
  level: "info"
  format: "json"
  output: "stdout"
```

#### 2. Policy Directory Setup
```bash
# Ensure policy directory exists
mkdir -p policies/

# Copy example policies
cp policies/privilege_escalation.policy policies/privilege_escalation.policy.bak
cp policies/malicious_file_access.policy policies/malicious_file_access.policy.bak

# Verify policy syntax
for policy in policies/*.policy; do
    echo "Validating $policy..."
    go run cmd/parser_example/main.go "$(cat $policy)"
done
```

### Running the System

#### 1. Development Mode
```bash
# Start with detailed logging
go run cmd/policyd_demo/main.go -verbose

# Expected output:
# [INFO] Starting ExecRay Tracer Policy Engine
# [INFO] Loading policies from: ./policies
# [INFO] Compiled policy: privilege_escalation (5 FSM states)
# [INFO] Compiled policy: malicious_file_access (7 FSM states)  
# [INFO] Policy engine ready, monitoring 2 policies
```

#### 2. Production Mode
```bash
# Build optimized binary
go build -ldflags="-s -w" -o execray-tracer cmd/policyd/main.go

# Run as systemd service
sudo ./execray-tracer -config config/production.yaml

# Or run with specific policies
sudo ./execray-tracer -policies policies/ -port 8080
```

#### 3. Container Deployment
```dockerfile
# Dockerfile for containerized deployment
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o execray-tracer cmd/policyd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/execray-tracer .
COPY policies/ policies/
CMD ["./execray-tracer"]
```

```bash
# Build and run container
docker build -t execray-tracer .
docker run --privileged -p 8080:8080 execray-tracer
```

### Troubleshooting

#### Common Issues

#### 1. Permission Denied (eBPF)
```bash
# Problem: Failed to load eBPF program
# Error: permission denied

# Solution 1: Run as root
sudo go run cmd/policyd_demo/main.go

# Solution 2: Check kernel version
uname -r
# Kernel must be >= 5.8 for unprivileged eBPF

# Solution 3: Check capabilities
getcap $(which go)
# Should show: cap_bpf,cap_sys_admin+ep
```

#### 2. Build Failures
```bash
# Problem: Missing dependencies
# Error: cannot find package

# Solution: Update modules
go clean -modcache
go mod download
go mod tidy

# Solution: Check Go version
go version
# Should be >= 1.19
```

#### 3. Policy Compilation Errors
```bash
# Problem: Policy fails to compile
# Error: syntax error at line X

# Solution: Validate syntax
go run cmd/parser_example/main.go "$(cat problematic.policy)"

# Check for common issues:
# - Missing quotes around patterns
# - Unmatched braces
# - Invalid syscall names
# - Malformed regex patterns
```

#### 4. Performance Issues
```bash
# Problem: High CPU usage or slow responses

# Solution 1: Check system resources
top
# Look for high CPU usage by go processes

# Solution 2: Reduce policy complexity
# Simplify regex patterns
# Reduce number of active policies
# Increase worker pool size

# Solution 3: Monitor metrics
curl http://localhost:8080/metrics
# Check latency and throughput metrics
```

### Monitoring & Maintenance

#### 1. Health Checks
```bash
# Basic health check endpoint
curl http://localhost:8080/health
# Expected: {"status": "ok", "policies": 3}

# Detailed status
curl http://localhost:8080/status
# Expected: Detailed system information

# Performance metrics
curl http://localhost:8080/metrics
# Expected: JSON metrics including latency, throughput, memory
```

#### 2. Log Monitoring
```bash
# Monitor system logs
tail -f /var/log/execray-tracer.log

# Key log patterns to watch:
# - "Policy compiled" (successful hot-reload)
# - "THREAT DETECTED" (security events)
# - "ERROR" (system issues)
# - "Performance degradation" (performance alerts)
```

#### 3. Policy Updates
```bash
# Hot-reload new policies (no restart required)
cp new_policy.policy policies/
# System automatically detects and compiles

# Verify policy loaded
curl http://localhost:8080/policies
# Expected: List including new policy

# Test policy
echo "test_content" | sudo tee /tmp/test_file
# Should trigger policy if pattern matches
```

### Performance Tuning

#### 1. For High-Volume Environments
```yaml
# config/high-volume.yaml
performance:
  worker_pool_size: 32          # Increase workers
  event_queue_size: 50000       # Larger event buffer
  ring_buffer_size: 1MB         # Larger eBPF buffer
  gc_target_percent: 50         # More frequent GC
  
policies:
  max_policies: 50              # Limit policy count
  pattern_cache_size: 10000     # Larger pattern cache
```

#### 2. For Low-Latency Requirements
```yaml
# config/low-latency.yaml  
performance:
  worker_pool_size: 16          # Optimal for most systems
  priority_scheduling: true     # Real-time scheduling
  memory_pool_enabled: true     # Object pooling
  
monitoring:
  metrics_interval: 1s          # Frequent monitoring
  latency_alert_threshold: 5ms  # Strict SLA
```

#### 3. For Development/Testing
```yaml
# config/development.yaml
logging:
  level: "debug"                # Verbose logging
  
policies:
  hot_reload: true              # Automatic reloading
  validation_strict: false      # Allow experimental policies
  
performance:
  worker_pool_size: 2           # Minimal workers for debugging
```

This setup guide ensures a smooth installation and configuration process for both evaluation and production deployment scenarios.
