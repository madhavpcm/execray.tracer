package compiler

import (
	"fmt"
	"regexp"
	"strings"
)

// TokenType represents the type of a token in the DSL
type TokenType int

const (
	// Special tokens
	ILLEGAL TokenType = iota
	EOF
	NEWLINE

	// Literals
	IDENT  // identifiers like "test", "example"
	STRING // string literals like "key_logger", "/dev/test.txt"
	REGEX  // regex patterns like "/dev.*"

	// Keywords
	PATH   // path
	BLOCK  // block
	OPENAT // openat
	EXECVE // execve
	WRITE  // write

	// Operators
	ASSIGN      // =
	REGEX_MATCH // =~
	QUESTION    // ?
	COLON       // :

	// Delimiters
	LBRACE // {
	RBRACE // }
	LPAREN // (
	RPAREN // )
	COMMA  // ,

	// Special operators
	ELLIPSIS_TWO   // ..
	ELLIPSIS_THREE // ...
)

// Token represents a single token in the DSL
type Token struct {
	Type     TokenType
	Literal  string
	Line     int
	Column   int
	Position int
}

// String returns a string representation of the token
func (t Token) String() string {
	return fmt.Sprintf("Token{Type: %s, Literal: %q, Line: %d, Column: %d}",
		t.Type.String(), t.Literal, t.Line, t.Column)
}

// String returns a string representation of the token type
func (tt TokenType) String() string {
	switch tt {
	case ILLEGAL:
		return "ILLEGAL"
	case EOF:
		return "EOF"
	case NEWLINE:
		return "NEWLINE"
	case IDENT:
		return "IDENT"
	case STRING:
		return "STRING"
	case REGEX:
		return "REGEX"
	case PATH:
		return "PATH"
	case BLOCK:
		return "BLOCK"
	case OPENAT:
		return "OPENAT"
	case EXECVE:
		return "EXECVE"
	case WRITE:
		return "WRITE"
	case ASSIGN:
		return "ASSIGN"
	case REGEX_MATCH:
		return "REGEX_MATCH"
	case QUESTION:
		return "QUESTION"
	case COLON:
		return "COLON"
	case LBRACE:
		return "LBRACE"
	case RBRACE:
		return "RBRACE"
	case LPAREN:
		return "LPAREN"
	case RPAREN:
		return "RPAREN"
	case COMMA:
		return "COMMA"
	case ELLIPSIS_TWO:
		return "ELLIPSIS_TWO"
	case ELLIPSIS_THREE:
		return "ELLIPSIS_THREE"
	default:
		return fmt.Sprintf("TokenType(%d)", int(tt))
	}
}

// Keywords maps keyword strings to their token types
var keywords = map[string]TokenType{
	"path":   PATH,
	"block":  BLOCK,
	"openat": OPENAT,
	"execve": EXECVE,
	"write":  WRITE,
}

// LookupIdent checks if an identifier is a keyword and returns the appropriate token type
func LookupIdent(ident string) TokenType {
	if tok, ok := keywords[ident]; ok {
		return tok
	}
	return IDENT
}

// Lexer represents the lexical analyzer for the DSL
type Lexer struct {
	input        string
	position     int  // current position in input (points to current char)
	readPosition int  // current reading position in input (after current char)
	ch           byte // current char under examination
	line         int  // current line number (1-indexed)
	column       int  // current column number (1-indexed)
}

// NewLexer creates a new lexer instance
func NewLexer(input string) *Lexer {
	l := &Lexer{
		input:  input,
		line:   1,
		column: 0,
	}
	l.readChar()
	return l
}

// readChar reads the next character and advances the position
func (l *Lexer) readChar() {
	if l.readPosition >= len(l.input) {
		l.ch = 0 // ASCII NUL character represents "EOF"
	} else {
		l.ch = l.input[l.readPosition]
	}
	l.position = l.readPosition
	l.readPosition++

	if l.ch == '\n' {
		l.line++
		l.column = 0
	} else {
		l.column++
	}
}

// peekChar returns the next character without advancing the position
func (l *Lexer) peekChar() byte {
	if l.readPosition >= len(l.input) {
		return 0
	}
	return l.input[l.readPosition]
}

// peekCharAt returns the character at the given offset from current position
func (l *Lexer) peekCharAt(offset int) byte {
	pos := l.readPosition + offset - 1
	if pos >= len(l.input) || pos < 0 {
		return 0
	}
	return l.input[pos]
}

// skipWhitespace skips whitespace characters except newlines
func (l *Lexer) skipWhitespace() {
	for l.ch == ' ' || l.ch == '\t' || l.ch == '\r' {
		l.readChar()
	}
}

// readIdentifier reads an identifier or keyword
func (l *Lexer) readIdentifier() string {
	position := l.position
	for isLetter(l.ch) || isDigit(l.ch) || l.ch == '_' {
		l.readChar()
	}
	return l.input[position:l.position]
}

// readString reads a string literal enclosed in double quotes
func (l *Lexer) readString() string {
	position := l.position + 1 // skip opening quote
	for {
		l.readChar()
		if l.ch == '"' || l.ch == 0 {
			break
		}
		// Handle escape sequences
		if l.ch == '\\' {
			l.readChar() // skip escaped character
		}
	}
	return l.input[position:l.position]
}

// readRegex reads a regex pattern after =~ operator
func (l *Lexer) readRegex() string {
	if l.ch != '"' {
		return ""
	}

	position := l.position + 1 // skip opening quote
	for {
		l.readChar()
		if l.ch == '"' || l.ch == 0 {
			break
		}
		// Handle escape sequences
		if l.ch == '\\' {
			l.readChar() // skip escaped character
		}
	}
	return l.input[position:l.position]
}

// isLetter checks if a character is a letter
func isLetter(ch byte) bool {
	return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z'
}

// isDigit checks if a character is a digit
func isDigit(ch byte) bool {
	return '0' <= ch && ch <= '9'
}

// NextToken scans the input and returns the next token
func (l *Lexer) NextToken() Token {
	var tok Token

	l.skipWhitespace()

	// Store current position for token
	tok.Line = l.line
	tok.Column = l.column
	tok.Position = l.position

	switch l.ch {
	case '=':
		if l.peekChar() == '~' {
			ch := l.ch
			l.readChar()
			tok = Token{Type: REGEX_MATCH, Literal: string(ch) + string(l.ch), Line: tok.Line, Column: tok.Column, Position: tok.Position}
		} else {
			tok = Token{Type: ASSIGN, Literal: string(l.ch), Line: tok.Line, Column: tok.Column, Position: tok.Position}
		}
	case '?':
		tok = Token{Type: QUESTION, Literal: string(l.ch), Line: tok.Line, Column: tok.Column, Position: tok.Position}
	case ':':
		tok = Token{Type: COLON, Literal: string(l.ch), Line: tok.Line, Column: tok.Column, Position: tok.Position}
	case '{':
		tok = Token{Type: LBRACE, Literal: string(l.ch), Line: tok.Line, Column: tok.Column, Position: tok.Position}
	case '}':
		tok = Token{Type: RBRACE, Literal: string(l.ch), Line: tok.Line, Column: tok.Column, Position: tok.Position}
	case '(':
		tok = Token{Type: LPAREN, Literal: string(l.ch), Line: tok.Line, Column: tok.Column, Position: tok.Position}
	case ')':
		tok = Token{Type: RPAREN, Literal: string(l.ch), Line: tok.Line, Column: tok.Column, Position: tok.Position}
	case ',':
		tok = Token{Type: COMMA, Literal: string(l.ch), Line: tok.Line, Column: tok.Column, Position: tok.Position}
	case '.':
		if l.peekChar() == '.' {
			if l.peekCharAt(2) == '.' {
				// Three dots: ...
				l.readChar() // consume second dot
				l.readChar() // consume third dot
				tok = Token{Type: ELLIPSIS_THREE, Literal: "...", Line: tok.Line, Column: tok.Column, Position: tok.Position}
			} else {
				// Two dots: ..
				l.readChar() // consume second dot
				tok = Token{Type: ELLIPSIS_TWO, Literal: "..", Line: tok.Line, Column: tok.Column, Position: tok.Position}
			}
		} else {
			tok = Token{Type: ILLEGAL, Literal: string(l.ch), Line: tok.Line, Column: tok.Column, Position: tok.Position}
		}
	case '"':
		tok.Type = STRING
		tok.Literal = l.readString()
		tok.Line = tok.Line
		tok.Column = tok.Column
		tok.Position = tok.Position
	case '\n':
		tok = Token{Type: NEWLINE, Literal: string(l.ch), Line: tok.Line, Column: tok.Column, Position: tok.Position}
	case 0:
		tok.Literal = ""
		tok.Type = EOF
		tok.Line = tok.Line
		tok.Column = tok.Column
		tok.Position = tok.Position
	default:
		if isLetter(l.ch) {
			tok.Literal = l.readIdentifier()
			tok.Type = LookupIdent(tok.Literal)
			tok.Line = tok.Line
			tok.Column = tok.Column
			tok.Position = tok.Position
			return tok // return early to avoid l.readChar() call
		} else {
			tok = Token{Type: ILLEGAL, Literal: string(l.ch), Line: tok.Line, Column: tok.Column, Position: tok.Position}
		}
	}

	l.readChar()
	return tok
}

// TokenizeRegex is a special method to handle regex patterns after =~ operator
func (l *Lexer) TokenizeRegex() Token {
	tok := Token{
		Line:     l.line,
		Column:   l.column,
		Position: l.position,
	}

	if l.ch == '"' {
		tok.Type = REGEX
		tok.Literal = l.readRegex()
		l.readChar() // consume closing quote
	} else {
		tok.Type = ILLEGAL
		tok.Literal = string(l.ch)
		l.readChar()
	}

	return tok
}

// Error represents a lexical error
type LexError struct {
	Message  string
	Line     int
	Column   int
	Position int
}

func (e LexError) Error() string {
	return fmt.Sprintf("lexical error at line %d, column %d: %s", e.Line, e.Column, e.Message)
}

// ValidateRegex validates that a regex pattern is syntactically correct
func ValidateRegex(pattern string) error {
	_, err := regexp.Compile(pattern)
	return err
}

// TokenizeInput tokenizes the entire input and returns a slice of tokens
func TokenizeInput(input string) ([]Token, error) {
	lexer := NewLexer(input)
	var tokens []Token
	var errors []LexError

	for {
		tok := lexer.NextToken()

		// If we encounter =~, the next string should be treated as a regex
		if tok.Type == REGEX_MATCH {
			tokens = append(tokens, tok)
			// Skip whitespace before regex
			lexer.skipWhitespace()
			regexTok := lexer.TokenizeRegex()

			// Validate regex patterns
			if regexTok.Type == REGEX {
				if err := ValidateRegex(regexTok.Literal); err != nil {
					errors = append(errors, LexError{
						Message:  fmt.Sprintf("invalid regex pattern: %v", err),
						Line:     regexTok.Line,
						Column:   regexTok.Column,
						Position: regexTok.Position,
					})
				}
			}

			tokens = append(tokens, regexTok)
			continue
		}

		tokens = append(tokens, tok)

		if tok.Type == EOF {
			break
		}
	}

	if len(errors) > 0 {
		var errorMessages []string
		for _, e := range errors {
			errorMessages = append(errorMessages, e.Error())
		}
		return tokens, fmt.Errorf("lexical errors: %s", strings.Join(errorMessages, "; "))
	}

	return tokens, nil
}
