# DSL Language Guide

## Overview

ExecRay Tracer uses a custom domain-specific language (DSL) designed specifically for defining cybersecurity policies. The language provides an intuitive syntax for describing malicious execution patterns, with powerful pattern matching and conditional logic capabilities.

## Language Specification

### Core Syntax

#### Policy Definition
Every policy must be defined within a `path` block with a unique identifier:

```dsl
path "policy_name" {
    // Policy rules go here
}
```

#### Basic Structure
```dsl
path "example_policy" {
    syscall_name { parameter_conditions }
    // ... additional syscalls and logic
}
```

### Supported Syscalls

#### 1. `openat` - File Operations
Monitors file opening operations with path and flag matching.

```dsl
openat { 
    pathname =~ "pattern"     // File path pattern matching
    flags == O_RDWR          // File access flags (optional)
}
```

**Examples:**
```dsl
// Monitor sensitive file access
openat { pathname =~ "/etc/(passwd|shadow)" }

// Detect temporary file creation
openat { pathname =~ "/tmp/.*\\.sh" }

// Monitor configuration files
openat { pathname =~ ".*\\.conf$" }
```

#### 2. `execve` - Process Execution  
Captures process execution events.

```dsl
execve {
    filename =~ "pattern"     // Executable path pattern
    argv[0] =~ "pattern"      // First argument pattern (optional)
}
```

**Examples:**
```dsl
// Detect shell execution
execve { filename =~ "/bin/(sh|bash|zsh)" }

// Monitor interpreter usage
execve { filename =~ ".*(python|perl|ruby)" }

// Detect specific commands
execve { argv[0] =~ "nc|netcat|curl|wget" }
```

#### 3. `write` - Data Writing
Monitors write operations with content pattern matching.

```dsl
write {
    content =~ "pattern"      // Data content pattern matching
    fd == number             // File descriptor (optional)
}
```

**Examples:**
```dsl
// Detect credential theft
write { content =~ ".*(password|secret|key).*" }

// Monitor script injection
write { content =~ ".*(eval|exec|system).*" }

// Detect data exfiltration  
write { content =~ ".*BEGIN.*PRIVATE.*KEY.*" }
```

### Pattern Matching

#### Regex Patterns
The DSL uses extended regular expressions for pattern matching:

```dsl
// Basic patterns
pathname =~ "test"           // Exact match
pathname =~ ".*test.*"       // Contains "test"
pathname =~ "^/tmp/"         // Starts with "/tmp/"
pathname =~ "\\.sh$"         // Ends with ".sh"

// Character classes
pathname =~ "[0-9]+"         // Numbers only
pathname =~ "[a-zA-Z_]+"     // Letters and underscore
pathname =~ "[^/]*"          // Anything except slash

// Alternation
pathname =~ "(jpg|png|gif)"  // Image files
filename =~ "(sh|bash|zsh)"  // Shell types
```

#### Advanced Patterns
```dsl
// Escape sequences
content =~ "\\\\x[0-9a-f]{2}"        // Hex escape codes
pathname =~ "\\.\\./\\.\\."          // Directory traversal

// Case-insensitive matching
content =~ "(?i)password"            // Case-insensitive

// Non-greedy matching
content =~ "BEGIN.*?END"             // Non-greedy match
```

### Conditional Logic

#### Basic Conditional Blocks
```dsl
path "conditional_example" {
    openat { pathname =~ "/sensitive/.*" } ?
    block "alert_block" {
        write { content =~ ".*" }
    } :
    block "normal_block" {
        // Normal processing
        execve { filename =~ "/bin/cat" }
    }
}
```

#### Multiple Conditions
```dsl
path "complex_conditions" {
    execve { filename =~ "/bin/sh" } ?
    block "shell_detected" {
        openat { pathname =~ "/etc/.*" } ?
        block "sensitive_access" {
            write { content =~ ".*root.*" }
        } :
        block "normal_shell" {
            // Benign shell usage
            ...
        }
    } :
    block "no_shell" {
        // Non-shell execution
        ...
    }
}
```

### Complete Policy Examples

#### 1. Privilege Escalation Detection
```dsl
path "privilege_escalation" {
    // Look for password file access
    openat { pathname =~ "/etc/(passwd|shadow)" }
    
    // Followed by modification attempts
    write { content =~ ".*(root|sudo|admin).*" }
}
```

#### 2. Reverse Shell Detection
```dsl
path "reverse_shell" {
    // Shell execution
    execve { filename =~ "/bin/(sh|bash)" }
    
    // With network-related arguments
    execve { argv[0] =~ ".*(nc|netcat|telnet).*" }
}
```

#### 3. Data Exfiltration Detection
```dsl
path "data_exfiltration" {
    // Access sensitive files
    openat { pathname =~ ".*\\.(key|pem|p12|crt)$" }
    
    // Then network transmission
    execve { filename =~ ".*(curl|wget|ssh|scp).*" }
}
```

#### 4. Keylogger Detection
```dsl
path "keylogger_activity" {
    // Input device access
    openat { pathname =~ "/dev/input/.*" } ?
    
    block "capture_keys" {
        // Log keystrokes
        write { content =~ ".*(key|stroke|input).*" }
    } :
    
    block "normal_input" {
        // Normal device access
        ...
    }
}
```

#### 5. Advanced Persistent Threat (APT)
```dsl
path "apt_backdoor" {
    // Create script in temporary location
    openat { pathname =~ "/tmp/.*\\.(sh|py|pl)$" }
    
    // Make executable  
    execve { filename =~ "/bin/chmod" }
    execve { argv[0] =~ "\\+x" }
    
    // Execute with privileges
    execve { filename =~ "/bin/sudo" } ?
    block "privileged_execution" {
        // Backdoor payload execution
        write { content =~ ".*(backdoor|payload|shell).*" }
    } :
    block "normal_execution" {
        // Regular script execution
        ...
    }
}
```

#### 6. Container Escape Detection
```dsl
path "container_escape" {
    // Access container runtime files
    openat { pathname =~ ".*/(docker|containerd|runc).*" }
    
    // Mount operations
    execve { filename =~ "/bin/mount" } ?
    block "mount_detected" {
        // Suspicious mount operations
        execve { argv[0] =~ ".*(proc|sys|dev).*" }
    } :
    block "no_mount" {
        // Other runtime access
        ...
    }
}
```

### Language Features

#### 1. State-Aware Execution
The DSL compiles to finite state machines, enabling complex pattern matching:

```
Policy: openat → write → execve
        ↓        ↓       ↓
States: INIT → OPEN → WRITE → EXEC → TERMINAL
```

#### 2. Hot-Reload Support
Policies can be modified and reloaded without system restart:

```bash
# Edit policy file
vim policies/new_policy.policy

# System automatically detects and recompiles
# Output: ✅ Policy reloaded: new_policy (3 FSM states)
```

#### 3. Error Handling
The compiler provides detailed error messages:

```dsl
path "bad_policy" {
    invalid_syscall { }  // Error: unknown syscall
    openat { badfield =~ "test" }  // Error: unknown field
}
```

**Error Output:**
```
Error: Line 2: Unknown syscall 'invalid_syscall'
Error: Line 3: Unknown field 'badfield' for syscall 'openat'
```

### Performance Considerations

#### 1. Pattern Complexity
- **Simple patterns** (literal strings): O(1) matching
- **Regex patterns**: O(n) where n is content length  
- **Complex regex**: May impact performance with large content

#### 2. State Machine Optimization
The compiler optimizes state machines:

```dsl
// Before optimization: 5 states
path "example" {
    openat { pathname =~ "test" }
    openat { pathname =~ "test" }  // Duplicate - will be merged
    write { content =~ "data" }
}

// After optimization: 3 states (duplicate removed)
```

#### 3. Memory Usage
- **Simple policies**: ~1KB per compiled FSM
- **Complex policies**: ~5-10KB per FSM
- **Pattern cache**: Shared across policies for efficiency

### Best Practices

#### 1. Policy Organization
```dsl
// Group related checks in single policy
path "web_attack_detection" {
    openat { pathname =~ ".*\\.(php|jsp|asp)$" }
    write { content =~ ".*(eval|exec|system|shell_exec).*" }
}

// Separate concerns for maintainability  
path "file_integrity" {
    openat { pathname =~ "/etc/.*" }
    write { content =~ ".*" }
}
```

#### 2. Pattern Efficiency
```dsl
// Efficient: Specific patterns
pathname =~ "/etc/passwd"

// Less efficient: Broad patterns
pathname =~ ".*"

// Balanced: Targeted with flexibility
pathname =~ "/etc/(passwd|shadow|group)"
```

#### 3. Conditional Logic
```dsl
// Good: Clear conditional flow
openat { pathname =~ "/sensitive/.*" } ?
block "alert" {
    write { content =~ ".*" }
} :
block "normal" {
    ...
}

// Avoid: Deep nesting (affects performance)
condition1 ? block { 
    condition2 ? block {
        condition3 ? block { ... } : block { ... }
    } : block { ... }
} : block { ... }
```

### Integration Examples

#### With External Tools
```dsl
path "siem_integration" {
    openat { pathname =~ "/var/log/.*" }
    write { content =~ ".*ERROR.*" }
    
    // Triggers can integrate with:
    // - Splunk alerts
    // - ELK stack processing  
    // - Custom webhook notifications
}
```

#### Testing Policies
```bash
# Validate syntax
go run cmd/parser_example/main.go 'path "test" { openat { pathname =~ "/tmp" } }'

# Test FSM generation  
go run cmd/fsm_example/main.go

# Live policy testing
go run cmd/policyd_demo/main.go
```

This DSL provides a powerful, intuitive way to define complex security policies with real-time compilation and execution capabilities, making it ideal for dynamic threat detection scenarios.
