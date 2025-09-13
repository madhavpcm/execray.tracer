package main

import (
	"fmt"
	"os"

	"execray.tracer/internal/compiler"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: parser_example <policy_content>")
		fmt.Println("Example: parser_example 'path \"test\" { openat { pathname=\"/dev/test\" } }'")
		os.Exit(1)
	}

	input := os.Args[1]

	fmt.Printf("Input: %s\n\n", input)

	// Parse the input
	program, err := compiler.ParseInput(input)
	if err != nil {
		fmt.Printf("Parse Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("AST Structure:")
	fmt.Printf("Program with %d policies:\n\n", len(program.Policies))

	for i, policy := range program.Policies {
		fmt.Printf("Policy %d: %s\n", i+1, policy.Name)
		fmt.Printf("  Position: %s\n", policy.Position())
		fmt.Printf("  Statements: %d\n", len(policy.Statements))

		for j, stmt := range policy.Statements {
			fmt.Printf("    Statement %d: %s\n", j+1, stmt.Type())
			fmt.Printf("      Position: %s\n", stmt.Position())

			switch s := stmt.(type) {
			case *compiler.SyscallStatement:
				fmt.Printf("      Syscall: %s\n", s.Name)
				fmt.Printf("      Parameters: %d\n", len(s.Parameters))
				for k, param := range s.Parameters {
					fmt.Printf("        Param %d: %s %s %s\n", k+1, param.Name, getOperatorString(param.Operator), param.Value.String())
				}
				if s.Repetition != nil {
					fmt.Printf("      Repetition: %s\n", s.Repetition.String())
				}
			case *compiler.BlockStatement:
				fmt.Printf("      Block: %s\n", s.Name)
				fmt.Printf("      Sub-statements: %d\n", len(s.Statements))
			case *compiler.ConditionalStatement:
				fmt.Printf("      Conditional:\n")
				fmt.Printf("        Condition: %s\n", s.Condition.Type())
				fmt.Printf("        Then: %s\n", s.ThenBlock.Type())
				fmt.Printf("        Else: %s\n", s.ElseBlock.Type())
			case *compiler.EllipsisStatement:
				fmt.Printf("      Ellipsis: %s\n", s.String())
			}
		}
		fmt.Println()
	}

	fmt.Println("AST String Representation:")
	fmt.Println(program.String())
}

func getOperatorString(op compiler.ParameterOperator) string {
	switch op {
	case compiler.AssignOp:
		return "="
	case compiler.RegexMatchOp:
		return "=~"
	default:
		return "?"
	}
}
