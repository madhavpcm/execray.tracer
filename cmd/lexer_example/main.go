package main

import (
	"fmt"
	"os"

	"execray.tracer/internal/compiler"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: lexer_example <policy_content>")
		fmt.Println("Example: lexer_example 'path \"test\" { openat { pathname=~\".*\" } }'")
		os.Exit(1)
	}

	input := os.Args[1]

	fmt.Printf("Input: %s\n\n", input)

	tokens, err := compiler.TokenizeInput(input)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		// Still show tokens even if there's an error
	}

	fmt.Println("Tokens:")
	for i, token := range tokens {
		fmt.Printf("%d: %s\n", i, token.String())
	}
}
