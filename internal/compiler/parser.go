package compiler

import (
	"fmt"
)

// Parser represents a recursive descent parser for the DSL
type Parser struct {
	tokens  []Token
	current int
	errors  []ParseError
}

// NewParser creates a new parser instance
func NewParser(tokens []Token) *Parser {
	return &Parser{
		tokens:  tokens,
		current: 0,
		errors:  make([]ParseError, 0),
	}
}

// Parse parses the tokens and returns the AST
func (p *Parser) Parse() (*Program, error) {
	program := &Program{
		Policies: make([]PolicyStatement, 0),
		Pos:      p.currentPosition(),
	}

	for !p.isAtEnd() {
		if p.match(NEWLINE) {
			continue // Skip newlines at top level
		}

		policy, err := p.parsePolicy()
		if err != nil {
			p.addError(err.(*ParseError))
			p.synchronize()
			continue
		}

		program.Policies = append(program.Policies, *policy)
	}

	if len(p.errors) > 0 {
		return program, &MultiParseError{Errors: p.errors}
	}

	return program, nil
}

// parsePolicy parses a path statement
func (p *Parser) parsePolicy() (*PolicyStatement, error) {
	pos := p.currentPosition()

	if !p.match(PATH) {
		return nil, p.error("expected 'path' keyword")
	}

	if !p.check(STRING) {
		return nil, p.error("expected policy name string after 'path'")
	}

	name := p.advance().Literal

	if !p.match(LBRACE) {
		return nil, p.error("expected '{' after policy name")
	}

	statements := make([]Statement, 0)

	for !p.check(RBRACE) && !p.isAtEnd() {
		if p.match(NEWLINE) {
			continue // Skip newlines
		}

		stmt, err := p.parseStatement()
		if err != nil {
			return nil, err
		}

		statements = append(statements, stmt)
	}

	if !p.match(RBRACE) {
		return nil, p.error("expected '}' after policy body")
	}

	return &PolicyStatement{
		Name:       name,
		Statements: statements,
		Pos:        pos,
	}, nil
}

// parseStatement parses any statement
func (p *Parser) parseStatement() (Statement, error) {
	// Check for conditional first (lookahead for ?)
	if p.isConditionalStatement() {
		return p.parseConditionalStatement()
	}

	// Check for block statement
	if p.check(BLOCK) {
		return p.parseBlockStatement()
	}

	// Check for syscall statements
	if p.check(OPENAT) || p.check(EXECVE) || p.check(WRITE) {
		return p.parseSyscallStatement()
	}

	// Check for ellipsis
	if p.check(ELLIPSIS_TWO) || p.check(ELLIPSIS_THREE) {
		return p.parseEllipsisStatement()
	}

	return nil, p.error(fmt.Sprintf("unexpected token: %s", p.peek().Type))
}

// parseBlockStatement parses a block statement
func (p *Parser) parseBlockStatement() (*BlockStatement, error) {
	pos := p.currentPosition()

	if !p.match(BLOCK) {
		return nil, p.error("expected 'block' keyword")
	}

	if !p.check(STRING) {
		return nil, p.error("expected block name string after 'block'")
	}

	name := p.advance().Literal

	if !p.match(LBRACE) {
		return nil, p.error("expected '{' after block name")
	}

	statements := make([]Statement, 0)

	for !p.check(RBRACE) && !p.isAtEnd() {
		if p.match(NEWLINE) {
			continue // Skip newlines
		}

		stmt, err := p.parseStatement()
		if err != nil {
			return nil, err
		}

		statements = append(statements, stmt)
	}

	if !p.match(RBRACE) {
		return nil, p.error("expected '}' after block body")
	}

	return &BlockStatement{
		Name:       name,
		Statements: statements,
		Pos:        pos,
	}, nil
}

// parseSyscallStatement parses a syscall statement
func (p *Parser) parseSyscallStatement() (*SyscallStatement, error) {
	pos := p.currentPosition()

	var name string
	if p.match(OPENAT) {
		name = "openat"
	} else if p.match(EXECVE) {
		name = "execve"
	} else if p.match(WRITE) {
		name = "write"
	} else {
		return nil, p.error("expected syscall name")
	}

	if !p.match(LBRACE) {
		return nil, p.error("expected '{' after syscall name")
	}

	parameters := make([]Parameter, 0)

	// Parse parameters
	for !p.check(RBRACE) && !p.isAtEnd() {
		if p.match(NEWLINE) {
			continue // Skip newlines
		}

		if len(parameters) > 0 && !p.match(COMMA) {
			// Parameters should be comma-separated, but it's optional in this grammar
		}

		param, err := p.parseParameter()
		if err != nil {
			return nil, err
		}

		parameters = append(parameters, *param)
	}

	if !p.match(RBRACE) {
		return nil, p.error("expected '}' after syscall parameters")
	}

	// Check for repetition modifier
	var repetition *RepetitionModifier
	if p.check(ELLIPSIS_TWO) {
		p.advance()
		repetition = &RepetitionModifier{
			RepType: RepetitionTwo,
			Pos:     p.previousPosition(),
		}
	} else if p.check(ELLIPSIS_THREE) {
		p.advance()
		repetition = &RepetitionModifier{
			RepType: RepetitionThree,
			Pos:     p.previousPosition(),
		}
	}

	return &SyscallStatement{
		Name:       name,
		Parameters: parameters,
		Repetition: repetition,
		Pos:        pos,
	}, nil
}

// parseParameter parses a parameter (name=value or name=~value)
func (p *Parser) parseParameter() (*Parameter, error) {
	pos := p.currentPosition()

	if !p.check(IDENT) {
		return nil, p.error("expected parameter name")
	}

	name := p.advance().Literal

	var operator ParameterOperator
	var value ParameterValue

	if p.match(ASSIGN) {
		operator = AssignOp

		if !p.check(STRING) {
			return nil, p.error("expected string value after '='")
		}

		valueToken := p.advance()
		value = &StringValue{
			Value: valueToken.Literal,
			Pos:   tokenToPosition(valueToken),
		}
	} else if p.match(REGEX_MATCH) {
		operator = RegexMatchOp

		if !p.check(REGEX) && !p.check(STRING) {
			return nil, p.error("expected regex pattern after '=~'")
		}

		valueToken := p.advance()
		if valueToken.Type == REGEX {
			value = &RegexValue{
				Pattern: valueToken.Literal,
				Pos:     tokenToPosition(valueToken),
			}
		} else {
			// STRING token that should be treated as regex
			value = &RegexValue{
				Pattern: valueToken.Literal,
				Pos:     tokenToPosition(valueToken),
			}
		}
	} else {
		return nil, p.error("expected '=' or '=~' after parameter name")
	}

	return &Parameter{
		Name:     name,
		Operator: operator,
		Value:    value,
		Pos:      pos,
	}, nil
}

// parseConditionalStatement parses a conditional statement (condition ? then : else)
func (p *Parser) parseConditionalStatement() (*ConditionalStatement, error) {
	pos := p.currentPosition()

	// Parse the condition (must be a syscall statement)
	condition, err := p.parseSyscallStatement()
	if err != nil {
		return nil, err
	}

	// Skip any newlines before ?
	for p.match(NEWLINE) {
		// skip
	}

	if !p.match(QUESTION) {
		return nil, p.error("expected '?' after condition")
	}

	// Skip any newlines after ?
	for p.match(NEWLINE) {
		// skip
	}

	// Parse then block
	thenBlock, err := p.parseStatement()
	if err != nil {
		return nil, err
	}

	// Skip any newlines before :
	for p.match(NEWLINE) {
		// skip
	}

	if !p.match(COLON) {
		return nil, p.error("expected ':' after then block")
	}

	// Skip any newlines after :
	for p.match(NEWLINE) {
		// skip
	}

	// Parse else block
	elseBlock, err := p.parseStatement()
	if err != nil {
		return nil, err
	}

	return &ConditionalStatement{
		Condition: condition,
		ThenBlock: thenBlock,
		ElseBlock: elseBlock,
		Pos:       pos,
	}, nil
} // parseEllipsisStatement parses ... or .. statements
func (p *Parser) parseEllipsisStatement() (*EllipsisStatement, error) {
	pos := p.currentPosition()

	var ellipsisType EllipsisType
	if p.match(ELLIPSIS_TWO) {
		ellipsisType = EllipsisTwo
	} else if p.match(ELLIPSIS_THREE) {
		ellipsisType = EllipsisThree
	} else {
		return nil, p.error("expected '...' or '..'")
	}

	return &EllipsisStatement{
		EllipsisType: ellipsisType,
		Pos:          pos,
	}, nil
}

// isConditionalStatement checks if the current position starts a conditional
func (p *Parser) isConditionalStatement() bool {
	// Simple lookahead: if we see a syscall followed by ?, it's conditional
	saved := p.current
	defer func() { p.current = saved }()

	// Check if we have a syscall
	if !p.check(OPENAT) && !p.check(EXECVE) && !p.check(WRITE) {
		return false
	}

	// Advance past syscall name
	p.advance()

	// Look for opening brace
	if !p.check(LBRACE) {
		return false
	}
	p.advance()

	// Skip parameters until closing brace
	braceCount := 1
	for !p.isAtEnd() && braceCount > 0 {
		if p.check(LBRACE) {
			braceCount++
		} else if p.check(RBRACE) {
			braceCount--
		}
		p.advance()
	}

	// Skip possible repetition modifiers
	if p.check(ELLIPSIS_TWO) || p.check(ELLIPSIS_THREE) {
		p.advance()
	}

	// Skip whitespace
	for p.check(NEWLINE) {
		p.advance()
	}

	// Check if next token is ?
	return p.check(QUESTION)
} // Helper methods

// match checks if current token matches any of the given types and advances if so
func (p *Parser) match(types ...TokenType) bool {
	for _, tokenType := range types {
		if p.check(tokenType) {
			p.advance()
			return true
		}
	}
	return false
}

// check returns true if current token is of the given type
func (p *Parser) check(tokenType TokenType) bool {
	if p.isAtEnd() {
		return false
	}
	return p.peek().Type == tokenType
}

// advance consumes and returns the current token
func (p *Parser) advance() Token {
	if !p.isAtEnd() {
		p.current++
	}
	return p.previous()
}

// isAtEnd checks if we're at the end of tokens
func (p *Parser) isAtEnd() bool {
	return p.peek().Type == EOF
}

// peek returns the current token without advancing
func (p *Parser) peek() Token {
	if p.current >= len(p.tokens) {
		return Token{Type: EOF, Literal: "", Line: 0, Column: 0}
	}
	return p.tokens[p.current]
}

// previous returns the previous token
func (p *Parser) previous() Token {
	if p.current == 0 {
		return Token{Type: ILLEGAL, Literal: "", Line: 0, Column: 0}
	}
	return p.tokens[p.current-1]
}

// currentPosition returns the current position
func (p *Parser) currentPosition() Position {
	return tokenToPosition(p.peek())
}

// previousPosition returns the previous token's position
func (p *Parser) previousPosition() Position {
	return tokenToPosition(p.previous())
}

// error creates a parse error
func (p *Parser) error(message string) *ParseError {
	tok := p.peek()
	return &ParseError{
		Message:  message,
		Position: tokenToPosition(tok),
		Token:    &tok,
	}
}

// addError adds an error to the error list
func (p *Parser) addError(err *ParseError) {
	p.errors = append(p.errors, *err)
}

// synchronize attempts to recover from parse errors
func (p *Parser) synchronize() {
	p.advance()

	for !p.isAtEnd() {
		if p.previous().Type == NEWLINE {
			return
		}

		switch p.peek().Type {
		case PATH, BLOCK, OPENAT, EXECVE, WRITE:
			return
		}

		p.advance()
	}
}

// MultiParseError represents multiple parse errors
type MultiParseError struct {
	Errors []ParseError
}

func (mpe *MultiParseError) Error() string {
	if len(mpe.Errors) == 1 {
		return mpe.Errors[0].Error()
	}

	msg := fmt.Sprintf("%d parse errors:\n", len(mpe.Errors))
	for i, err := range mpe.Errors {
		msg += fmt.Sprintf("  %d. %s\n", i+1, err.Error())
	}
	return msg
}

// ParseInput parses input text and returns an AST
func ParseInput(input string) (*Program, error) {
	tokens, err := TokenizeInput(input)
	if err != nil {
		return nil, fmt.Errorf("tokenization failed: %w", err)
	}

	parser := NewParser(tokens)
	return parser.Parse()
}
