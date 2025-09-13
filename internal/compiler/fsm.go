package compiler

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"execray.tracer/pkg/ipc"
	"execray.tracer/pkg/syscalls"
)

// StateType represents the different types of FSM states
type StateType int

const (
	InitialStateType StateType = iota
	SyscallStateType
	ConditionalStateType
	TerminalStateType
	BlockStateType
)

// State represents a node in the finite state machine
type State interface {
	Type() StateType
	ID() string
	Evaluate(event *ipc.BpfSyscallEvent) (bool, error)
	GetTransitions() []Transition
	SetTransitions([]Transition)
	String() string
}

// Transition represents a transition between states
type Transition struct {
	TargetState string // State ID to transition to
	Condition   string // Optional condition for transition
}

// BaseState provides common functionality for all state types
type BaseState struct {
	id          string
	transitions []Transition
}

func (s *BaseState) ID() string {
	return s.id
}

func (s *BaseState) GetTransitions() []Transition {
	return s.transitions
}

func (s *BaseState) SetTransitions(transitions []Transition) {
	s.transitions = transitions
}

// InitialState represents the starting state of the FSM
type InitialState struct {
	BaseState
}

func NewInitialState(id string) *InitialState {
	return &InitialState{
		BaseState: BaseState{id: id},
	}
}

func (s *InitialState) Type() StateType {
	return InitialStateType
}

func (s *InitialState) Evaluate(event *ipc.BpfSyscallEvent) (bool, error) {
	// Initial state always matches - just passes through to next state
	return true, nil
}

func (s *InitialState) String() string {
	return fmt.Sprintf("InitialState[%s]", s.id)
}

// SyscallState represents a state that matches against a specific syscall
type SyscallState struct {
	BaseState
	SyscallName string
	Parameters  []ParameterMatcher
}

func NewSyscallState(id, syscallName string, parameters []ParameterMatcher) *SyscallState {
	return &SyscallState{
		BaseState:   BaseState{id: id},
		SyscallName: syscallName,
		Parameters:  parameters,
	}
}

func (s *SyscallState) Type() StateType {
	return SyscallStateType
}

func (s *SyscallState) Evaluate(event *ipc.BpfSyscallEvent) (bool, error) {
	// Check if syscall matches
	expectedSyscallNr, err := getSyscallNumber(s.SyscallName)
	if err != nil {
		return false, fmt.Errorf("unknown syscall %s: %v", s.SyscallName, err)
	}

	if event.SyscallNr != expectedSyscallNr {
		return false, nil
	}

	// Parse syscall-specific data for parameter matching
	parser, err := syscalls.SyscallParser(event.SyscallNr)
	if err != nil {
		return false, fmt.Errorf("no parser for syscall %d: %v", event.SyscallNr, err)
	}

	syscallData := parser()
	reader := bytes.NewReader(event.Data[:])
	if err := syscallData.Parse(reader); err != nil {
		return false, fmt.Errorf("failed to parse syscall data: %v", err)
	}

	// Evaluate all parameter matchers
	for _, paramMatcher := range s.Parameters {
		if !paramMatcher.Matches(syscallData) {
			return false, nil
		}
	}

	return true, nil
}

func (s *SyscallState) String() string {
	return fmt.Sprintf("SyscallState[%s:%s]", s.id, s.SyscallName)
}

// ConditionalState represents a state with conditional logic
type ConditionalState struct {
	BaseState
	Condition       string
	TrueTransition  string
	FalseTransition string
}

func NewConditionalState(id, condition, trueTransition, falseTransition string) *ConditionalState {
	return &ConditionalState{
		BaseState:       BaseState{id: id},
		Condition:       condition,
		TrueTransition:  trueTransition,
		FalseTransition: falseTransition,
	}
}

func (s *ConditionalState) Type() StateType {
	return ConditionalStateType
}

func (s *ConditionalState) Evaluate(event *ipc.BpfSyscallEvent) (bool, error) {
	// For now, conditional states always evaluate to true
	// The actual conditional logic will be handled during FSM compilation
	return true, nil
}

func (s *ConditionalState) String() string {
	return fmt.Sprintf("ConditionalState[%s:%s]", s.id, s.Condition)
}

// TerminalState represents an end state (match or no-match)
type TerminalState struct {
	BaseState
	MatchResult bool
}

func NewTerminalState(id string, matchResult bool) *TerminalState {
	return &TerminalState{
		BaseState:   BaseState{id: id},
		MatchResult: matchResult,
	}
}

func (s *TerminalState) Type() StateType {
	return TerminalStateType
}

func (s *TerminalState) Evaluate(event *ipc.BpfSyscallEvent) (bool, error) {
	return s.MatchResult, nil
}

func (s *TerminalState) String() string {
	result := "REJECT"
	if s.MatchResult {
		result = "MATCH"
	}
	return fmt.Sprintf("TerminalState[%s:%s]", s.id, result)
}

// BlockState represents a named block that can be referenced
type BlockState struct {
	BaseState
	BlockName string
}

func NewBlockState(id, blockName string) *BlockState {
	return &BlockState{
		BaseState: BaseState{id: id},
		BlockName: blockName,
	}
}

func (s *BlockState) Type() StateType {
	return BlockStateType
}

func (s *BlockState) Evaluate(event *ipc.BpfSyscallEvent) (bool, error) {
	// Block states are just markers - they pass through
	return true, nil
}

func (s *BlockState) String() string {
	return fmt.Sprintf("BlockState[%s:%s]", s.id, s.BlockName)
}

// ParameterMatcher interface for matching syscall parameters
type ParameterMatcher interface {
	Matches(syscallData syscalls.SyscallDataParser) bool
	String() string
}

// StringParameterMatcher matches string parameters exactly
type StringParameterMatcher struct {
	ParameterName string
	ExpectedValue string
}

func (m *StringParameterMatcher) Matches(syscallData syscalls.SyscallDataParser) bool {
	value := extractParameterValue(syscallData, m.ParameterName)
	return value == m.ExpectedValue
}

func (m *StringParameterMatcher) String() string {
	return fmt.Sprintf("%s=%q", m.ParameterName, m.ExpectedValue)
}

// RegexParameterMatcher matches string parameters against regex
type RegexParameterMatcher struct {
	ParameterName string
	Pattern       *regexp.Regexp
}

func (m *RegexParameterMatcher) Matches(syscallData syscalls.SyscallDataParser) bool {
	value := extractParameterValue(syscallData, m.ParameterName)
	return m.Pattern.MatchString(value)
}

func (m *RegexParameterMatcher) String() string {
	return fmt.Sprintf("%s=~/%s/", m.ParameterName, m.Pattern.String())
}

// NumericParameterMatcher matches numeric parameters
type NumericParameterMatcher struct {
	ParameterName string
	ExpectedValue int64
}

func (m *NumericParameterMatcher) Matches(syscallData syscalls.SyscallDataParser) bool {
	valueStr := extractParameterValue(syscallData, m.ParameterName)
	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		return false
	}
	return value == m.ExpectedValue
}

func (m *NumericParameterMatcher) String() string {
	return fmt.Sprintf("%s=%d", m.ParameterName, m.ExpectedValue)
}

// Helper functions

func getSyscallNumber(syscallName string) (uint64, error) {
	switch strings.ToLower(syscallName) {
	case "openat":
		return syscalls.SYS_OPENAT, nil
	case "execve":
		return syscalls.SYS_EXECVE, nil
	case "write":
		return syscalls.SYS_WRITE, nil
	default:
		return 0, fmt.Errorf("unknown syscall: %s", syscallName)
	}
}

func extractParameterValue(syscallData syscalls.SyscallDataParser, paramName string) string {
	// Since the actual event types are unexported, we'll parse the String() output
	str := syscallData.String()

	// Determine syscall type from string prefix and extract parameter
	if strings.HasPrefix(str, "openat") {
		switch paramName {
		case "pathname", "path":
			return extractOpenatPathname(syscallData)
		}
	} else if strings.HasPrefix(str, "execve") {
		switch paramName {
		case "filename", "path":
			return extractExecveFilename(syscallData)
		}
	} else if strings.HasPrefix(str, "write") {
		switch paramName {
		case "content", "buf":
			return extractWriteContent(syscallData)
		case "len", "length":
			return fmt.Sprintf("%d", extractWriteLength(syscallData))
		}
	}
	return ""
}

// We need to use reflection or interface casting since the syscall types are in another package
// For now, we'll use string parsing from the String() method
func extractOpenatPathname(data syscalls.SyscallDataParser) string {
	str := data.String()
	// Parse "openat, Path: /some/path" format
	if idx := strings.Index(str, "Path: "); idx != -1 {
		return str[idx+6:]
	}
	return ""
}

func extractExecveFilename(data syscalls.SyscallDataParser) string {
	str := data.String()
	// Parse "execve, Filename: /some/path" format
	if idx := strings.Index(str, "Filename: "); idx != -1 {
		return str[idx+10:]
	}
	return ""
}

func extractWriteContent(data syscalls.SyscallDataParser) string {
	str := data.String()
	// Parse "write, Len: 123, Content: "some content"" format
	if idx := strings.Index(str, "Content: "); idx != -1 {
		content := str[idx+9:]
		// Remove quotes if present
		if len(content) >= 2 && content[0] == '"' && content[len(content)-1] == '"' {
			return content[1 : len(content)-1]
		}
		return content
	}
	return ""
}

func extractWriteLength(data syscalls.SyscallDataParser) int64 {
	str := data.String()
	// Parse "write, Len: 123, Content: ..." format
	if idx := strings.Index(str, "Len: "); idx != -1 {
		lenStr := str[idx+5:]
		if commaIdx := strings.Index(lenStr, ","); commaIdx != -1 {
			lenStr = lenStr[:commaIdx]
		}
		if val, err := strconv.ParseInt(strings.TrimSpace(lenStr), 10, 64); err == nil {
			return val
		}
	}
	return 0
}
