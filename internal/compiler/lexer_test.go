package compiler

import (
	"testing"
)

func TestLexer_BasicTokens(t *testing.T) {
	input := `path "key_logger" { block "openat_example" { openat { pathname="/dev/test.txt" } openat { pathname=~"/dev.*" } } }`

	expectedTokens := []struct {
		expectedType    TokenType
		expectedLiteral string
	}{
		{PATH, "path"},
		{STRING, "key_logger"},
		{LBRACE, "{"},
		{BLOCK, "block"},
		{STRING, "openat_example"},
		{LBRACE, "{"},
		{OPENAT, "openat"},
		{LBRACE, "{"},
		{IDENT, "pathname"},
		{ASSIGN, "="},
		{STRING, "/dev/test.txt"},
		{RBRACE, "}"},
		{OPENAT, "openat"},
		{LBRACE, "{"},
		{IDENT, "pathname"},
		{REGEX_MATCH, "=~"},
		{REGEX, "/dev.*"},
		{RBRACE, "}"},
		{RBRACE, "}"},
		{RBRACE, "}"},
		{EOF, ""},
	}

	tokens, err := TokenizeInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tokens) != len(expectedTokens) {
		t.Fatalf("expected %d tokens, got %d", len(expectedTokens), len(tokens))
	}

	for i, expectedToken := range expectedTokens {
		tok := tokens[i]

		if tok.Type != expectedToken.expectedType {
			t.Fatalf("tests[%d] - tokentype wrong. expected=%q, got=%q",
				i, expectedToken.expectedType, tok.Type)
		}

		if tok.Literal != expectedToken.expectedLiteral {
			t.Fatalf("tests[%d] - literal wrong. expected=%q, got=%q",
				i, expectedToken.expectedLiteral, tok.Literal)
		}
	}
}

func TestLexer_ConditionalBlock(t *testing.T) {
	input := `openat { pathname=~"syscall" } ? block "ifcase" { execve { pathname =~ "sudo" } write {}.. } : block "elsecase" { ... }`

	expectedTokens := []TokenType{
		OPENAT, LBRACE, IDENT, REGEX_MATCH, REGEX, RBRACE, QUESTION,
		BLOCK, STRING, LBRACE,
		EXECVE, LBRACE, IDENT, REGEX_MATCH, REGEX, RBRACE,
		WRITE, LBRACE, RBRACE, ELLIPSIS_TWO,
		RBRACE, COLON,
		BLOCK, STRING, LBRACE,
		ELLIPSIS_THREE,
		RBRACE,
		EOF,
	}

	tokens, err := TokenizeInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tokens) != len(expectedTokens) {
		t.Fatalf("expected %d tokens, got %d", len(expectedTokens), len(tokens))
	}

	for i, expectedType := range expectedTokens {
		tok := tokens[i]
		if tok.Type != expectedType {
			t.Fatalf("tests[%d] - tokentype wrong. expected=%q, got=%q (literal: %q)",
				i, expectedType, tok.Type, tok.Literal)
		}
	}
}

func TestLexer_ErrorHandling(t *testing.T) {
	// Test invalid regex pattern
	input := `openat { pathname=~"[invalid" }`

	tokens, err := TokenizeInput(input)
	if err == nil {
		t.Fatal("expected error for invalid regex pattern")
	}

	// Should still have tokenized the input
	if len(tokens) == 0 {
		t.Fatal("expected tokens even with error")
	}

	// Check that we have the expected tokens
	expectedTypes := []TokenType{OPENAT, LBRACE, IDENT, REGEX_MATCH, REGEX, RBRACE, EOF}
	if len(tokens) != len(expectedTypes) {
		t.Fatalf("expected %d tokens, got %d", len(expectedTypes), len(tokens))
	}

	for i, expectedType := range expectedTypes {
		if tokens[i].Type != expectedType {
			t.Fatalf("token[%d]: expected %q, got %q", i, expectedType, tokens[i].Type)
		}
	}
}

func TestLexer_StringLiterals(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`"simple"`, "simple"},
		{`"path/with/slashes"`, "path/with/slashes"},
		{`"/dev/.*"`, "/dev/.*"},
		{`"escaped\"quote"`, `escaped\"quote`},
	}

	for _, tt := range tests {
		lexer := NewLexer(tt.input)
		tok := lexer.NextToken()

		if tok.Type != STRING {
			t.Fatalf("expected STRING token, got %q", tok.Type)
		}

		if tok.Literal != tt.expected {
			t.Fatalf("expected %q, got %q", tt.expected, tok.Literal)
		}
	}
}

func TestLexer_Ellipsis(t *testing.T) {
	tests := []struct {
		input        string
		expectedType TokenType
	}{
		{"..", ELLIPSIS_TWO},
		{"...", ELLIPSIS_THREE},
		{".", ILLEGAL}, // single dot should be illegal
	}

	for _, tt := range tests {
		lexer := NewLexer(tt.input)
		tok := lexer.NextToken()

		if tok.Type != tt.expectedType {
			t.Fatalf("input %q: expected %q, got %q", tt.input, tt.expectedType, tok.Type)
		}
	}
}

func TestLexer_LineAndColumnTracking(t *testing.T) {
	input := `path "test"
{
    openat
}`

	lexer := NewLexer(input)

	// First token should be at line 1, column 1
	tok := lexer.NextToken()
	if tok.Line != 1 || tok.Column != 1 {
		t.Fatalf("expected line 1, column 1, got line %d, column %d", tok.Line, tok.Column)
	}

	// Skip to newline
	lexer.NextToken()       // STRING "test"
	tok = lexer.NextToken() // NEWLINE
	if tok.Type != NEWLINE {
		t.Fatalf("expected NEWLINE, got %q", tok.Type)
	}

	// Next token should be at line 2
	tok = lexer.NextToken() // LBRACE
	if tok.Line != 2 {
		t.Fatalf("expected line 2, got line %d", tok.Line)
	}
}

func TestLexer_Keywords(t *testing.T) {
	keywords := map[string]TokenType{
		"path":   PATH,
		"block":  BLOCK,
		"openat": OPENAT,
		"execve": EXECVE,
		"write":  WRITE,
	}

	for keyword, expectedType := range keywords {
		lexer := NewLexer(keyword)
		tok := lexer.NextToken()

		if tok.Type != expectedType {
			t.Fatalf("keyword %q: expected %q, got %q", keyword, expectedType, tok.Type)
		}

		if tok.Literal != keyword {
			t.Fatalf("keyword %q: expected literal %q, got %q", keyword, keyword, tok.Literal)
		}
	}
}

func TestTokenizeInput(t *testing.T) {
	input := `path "test" {
    openat { pathname="/valid" }
}`

	tokens, err := TokenizeInput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tokens) == 0 {
		t.Fatal("expected tokens, got none")
	}

	// Last token should be EOF
	lastToken := tokens[len(tokens)-1]
	if lastToken.Type != EOF {
		t.Fatalf("expected last token to be EOF, got %q", lastToken.Type)
	}
}
