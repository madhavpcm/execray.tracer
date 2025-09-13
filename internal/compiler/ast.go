package compiler

import (
	"fmt"
	"strings"
)

// ASTNode represents a node in the Abstract Syntax Tree
type ASTNode interface {
	String() string
	Type() string
	Position() Position
}

// Position represents the position in the source code
type Position struct {
	Line   int
	Column int
	Offset int
}

func (p Position) String() string {
	return fmt.Sprintf("line %d, column %d", p.Line, p.Column)
}

// Program represents the root of the AST
type Program struct {
	Policies []PolicyStatement
	Pos      Position
}

func (p *Program) String() string {
	var out strings.Builder
	for _, policy := range p.Policies {
		out.WriteString(policy.String())
		out.WriteString("\n")
	}
	return out.String()
}

func (p *Program) Type() string       { return "Program" }
func (p *Program) Position() Position { return p.Pos }

// PolicyStatement represents a path statement (top-level policy)
type PolicyStatement struct {
	Name       string
	Statements []Statement
	Pos        Position
}

func (ps *PolicyStatement) String() string {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("path \"%s\" {\n", ps.Name))
	for _, stmt := range ps.Statements {
		lines := strings.Split(stmt.String(), "\n")
		for _, line := range lines {
			if line != "" {
				out.WriteString("  " + line + "\n")
			}
		}
	}
	out.WriteString("}")
	return out.String()
}

func (ps *PolicyStatement) Type() string       { return "PolicyStatement" }
func (ps *PolicyStatement) Position() Position { return ps.Pos }

// Statement represents any statement in the DSL
type Statement interface {
	ASTNode
	statement()
}

// BlockStatement represents a named block
type BlockStatement struct {
	Name       string
	Statements []Statement
	Pos        Position
}

func (bs *BlockStatement) String() string {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("block \"%s\" {\n", bs.Name))
	for _, stmt := range bs.Statements {
		lines := strings.Split(stmt.String(), "\n")
		for _, line := range lines {
			if line != "" {
				out.WriteString("  " + line + "\n")
			}
		}
	}
	out.WriteString("}")
	return out.String()
}

func (bs *BlockStatement) Type() string       { return "BlockStatement" }
func (bs *BlockStatement) Position() Position { return bs.Pos }
func (bs *BlockStatement) statement()         {}

// SyscallStatement represents a syscall invocation
type SyscallStatement struct {
	Name       string // openat, execve, write
	Parameters []Parameter
	Repetition *RepetitionModifier
	Pos        Position
}

func (ss *SyscallStatement) String() string {
	var out strings.Builder
	out.WriteString(ss.Name)
	out.WriteString(" { ")

	for i, param := range ss.Parameters {
		if i > 0 {
			out.WriteString(", ")
		}
		out.WriteString(param.String())
	}

	out.WriteString(" }")

	if ss.Repetition != nil {
		out.WriteString(ss.Repetition.String())
	}

	return out.String()
}

func (ss *SyscallStatement) Type() string       { return "SyscallStatement" }
func (ss *SyscallStatement) Position() Position { return ss.Pos }
func (ss *SyscallStatement) statement()         {}

// ConditionalStatement represents a conditional block (? ... : ...)
type ConditionalStatement struct {
	Condition Statement
	ThenBlock Statement
	ElseBlock Statement
	Pos       Position
}

func (cs *ConditionalStatement) String() string {
	var out strings.Builder
	out.WriteString(cs.Condition.String())
	out.WriteString(" ?\n")

	lines := strings.Split(cs.ThenBlock.String(), "\n")
	for _, line := range lines {
		if line != "" {
			out.WriteString("  " + line + "\n")
		}
	}

	out.WriteString(" :\n")

	lines = strings.Split(cs.ElseBlock.String(), "\n")
	for _, line := range lines {
		if line != "" {
			out.WriteString("  " + line + "\n")
		}
	}

	return out.String()
}

func (cs *ConditionalStatement) Type() string       { return "ConditionalStatement" }
func (cs *ConditionalStatement) Position() Position { return cs.Pos }
func (cs *ConditionalStatement) statement()         {}

// EllipsisStatement represents ... (continuation placeholder)
type EllipsisStatement struct {
	EllipsisType EllipsisType
	Pos          Position
}

type EllipsisType int

const (
	EllipsisTwo   EllipsisType = iota // ..
	EllipsisThree                     // ...
)

func (es *EllipsisStatement) String() string {
	if es.EllipsisType == EllipsisTwo {
		return ".."
	}
	return "..."
}

func (es *EllipsisStatement) Type() string       { return "EllipsisStatement" }
func (es *EllipsisStatement) Position() Position { return es.Pos }
func (es *EllipsisStatement) statement()         {}

// Parameter represents a parameter in a syscall
type Parameter struct {
	Name     string
	Operator ParameterOperator
	Value    ParameterValue
	Pos      Position
}

type ParameterOperator int

const (
	AssignOp     ParameterOperator = iota // =
	RegexMatchOp                          // =~
)

func (p *Parameter) String() string {
	var op string
	switch p.Operator {
	case AssignOp:
		op = "="
	case RegexMatchOp:
		op = "=~"
	}
	return fmt.Sprintf("%s%s%s", p.Name, op, p.Value.String())
}

func (p *Parameter) Type() string       { return "Parameter" }
func (p *Parameter) Position() Position { return p.Pos }

// ParameterValue represents the value of a parameter
type ParameterValue interface {
	String() string
	Type() string
	Position() Position
}

// StringValue represents a string literal value
type StringValue struct {
	Value string
	Pos   Position
}

func (sv *StringValue) String() string     { return fmt.Sprintf("\"%s\"", sv.Value) }
func (sv *StringValue) Type() string       { return "StringValue" }
func (sv *StringValue) Position() Position { return sv.Pos }

// RegexValue represents a regex pattern value
type RegexValue struct {
	Pattern string
	Pos     Position
}

func (rv *RegexValue) String() string     { return fmt.Sprintf("\"%s\"", rv.Pattern) }
func (rv *RegexValue) Type() string       { return "RegexValue" }
func (rv *RegexValue) Position() Position { return rv.Pos }

// RepetitionModifier represents .. or ... after statements
type RepetitionModifier struct {
	RepType RepetitionType
	Pos     Position
}

type RepetitionType int

const (
	RepetitionTwo   RepetitionType = iota // ..
	RepetitionThree                       // ...
)

func (rm *RepetitionModifier) String() string {
	if rm.RepType == RepetitionTwo {
		return ".."
	}
	return "..."
}

func (rm *RepetitionModifier) Type() string       { return "RepetitionModifier" }
func (rm *RepetitionModifier) Position() Position { return rm.Pos }

// ParseError represents a parsing error
type ParseError struct {
	Message  string
	Position Position
	Token    *Token
}

func (pe *ParseError) Error() string {
	if pe.Token != nil {
		return fmt.Sprintf("parse error at %s: %s (got token: %s)",
			pe.Position, pe.Message, pe.Token.Type)
	}
	return fmt.Sprintf("parse error at %s: %s", pe.Position, pe.Message)
}

// Helper function to convert token position to AST position
func tokenToPosition(tok Token) Position {
	return Position{
		Line:   tok.Line,
		Column: tok.Column,
		Offset: tok.Position,
	}
}
