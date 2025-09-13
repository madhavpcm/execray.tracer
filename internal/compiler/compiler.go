package compiler

import (
	"fmt"
	"regexp"
)

// FSM represents a compiled finite state machine
type FSM struct {
	States       map[string]State
	InitialState string
	CurrentState string
}

// NewFSM creates a new empty FSM
func NewFSM() *FSM {
	return &FSM{
		States: make(map[string]State),
	}
}

// AddState adds a state to the FSM
func (fsm *FSM) AddState(state State) {
	fsm.States[state.ID()] = state
}

// SetInitialState sets the initial state of the FSM
func (fsm *FSM) SetInitialState(stateID string) {
	fsm.InitialState = stateID
	fsm.CurrentState = stateID
}

// Reset resets the FSM to its initial state
func (fsm *FSM) Reset() {
	fsm.CurrentState = fsm.InitialState
}

// Compiler compiles AST nodes into FSM states
type Compiler struct {
	nextStateID int
	fsm         *FSM
}

// NewCompiler creates a new AST-to-FSM compiler
func NewCompiler() *Compiler {
	return &Compiler{
		nextStateID: 0,
		fsm:         NewFSM(),
	}
}

// Compile compiles a Program AST node into an FSM
func (c *Compiler) Compile(program *Program) (*FSM, error) {
	// Create initial state
	initialState := NewInitialState(c.generateStateID("initial"))
	c.fsm.AddState(initialState)
	c.fsm.SetInitialState(initialState.ID())

	// Compile each policy statement
	var currentStateID = initialState.ID()
	var terminalStateID string

	for i, policy := range program.Policies {
		// Create a terminal state for this policy
		terminalStateID = c.generateStateID("terminal")
		terminalState := NewTerminalState(terminalStateID, true) // Match found
		c.fsm.AddState(terminalState)

		// Compile the policy statements
		nextStateID, err := c.compileStatements(policy.Statements, currentStateID, terminalStateID)
		if err != nil {
			return nil, fmt.Errorf("failed to compile policy %d: %v", i, err)
		}

		// For multiple policies, we need to create branches
		if i < len(program.Policies)-1 {
			// Create a new initial state for the next policy
			nextInitialStateID := c.generateStateID("initial")
			nextInitialState := NewInitialState(nextInitialStateID)
			c.fsm.AddState(nextInitialState)
			currentStateID = nextInitialStateID
		} else {
			currentStateID = nextStateID
		}
	}

	// Add a final reject state if no policies match
	if terminalStateID == "" {
		rejectState := NewTerminalState(c.generateStateID("reject"), false)
		c.fsm.AddState(rejectState)
	}

	return c.fsm, nil
}

// compileStatements compiles a slice of statements into FSM states
func (c *Compiler) compileStatements(statements []Statement, startStateID, endStateID string) (string, error) {
	if len(statements) == 0 {
		// No statements, just connect start to end
		if startState, exists := c.fsm.States[startStateID]; exists {
			transitions := startState.GetTransitions()
			transitions = append(transitions, Transition{TargetState: endStateID})
			startState.SetTransitions(transitions)
		}
		return endStateID, nil
	}

	currentStateID := startStateID

	for i, stmt := range statements {
		var nextStateID string
		if i == len(statements)-1 {
			// Last statement should transition to end state
			nextStateID = endStateID
		} else {
			// Create intermediate state
			nextStateID = c.generateStateID("stmt")
			intermediateState := NewInitialState(nextStateID) // Pass-through state
			c.fsm.AddState(intermediateState)
		}

		_, err := c.compileStatement(stmt, currentStateID, nextStateID)
		if err != nil {
			return "", fmt.Errorf("failed to compile statement %d: %v", i, err)
		}

		currentStateID = nextStateID
	}

	return currentStateID, nil
}

// compileStatement compiles a single statement
func (c *Compiler) compileStatement(stmt Statement, currentStateID, nextStateID string) (string, error) {
	switch s := stmt.(type) {
	case *SyscallStatement:
		return c.compileSyscallStatement(s, currentStateID, nextStateID)
	case *BlockStatement:
		return c.compileBlockStatement(s, currentStateID, nextStateID)
	case *ConditionalStatement:
		return c.compileConditionalStatement(s, currentStateID, nextStateID)
	case *EllipsisStatement:
		return c.compileEllipsisStatement(s, currentStateID, nextStateID)
	default:
		return "", fmt.Errorf("unsupported statement type: %T", stmt)
	}
}

// compileSyscallStatement compiles a syscall statement into a SyscallState
func (c *Compiler) compileSyscallStatement(stmt *SyscallStatement, currentStateID, nextStateID string) (string, error) {
	// Create parameter matchers
	var paramMatchers []ParameterMatcher
	for _, param := range stmt.Parameters {
		matcher, err := c.compileParameter(param)
		if err != nil {
			return "", fmt.Errorf("failed to compile parameter: %v", err)
		}
		paramMatchers = append(paramMatchers, matcher)
	}

	// Create syscall state
	stateID := c.generateStateID("syscall")
	syscallState := NewSyscallState(stateID, stmt.Name, paramMatchers)

	// Add transition to next state
	syscallState.SetTransitions([]Transition{{TargetState: nextStateID}})

	c.fsm.AddState(syscallState)

	// Connect current state to this new state
	if currentState, exists := c.fsm.States[currentStateID]; exists {
		transitions := currentState.GetTransitions()
		transitions = append(transitions, Transition{TargetState: stateID})
		currentState.SetTransitions(transitions)
	}

	return nextStateID, nil
}

// compileBlockStatement compiles a block statement
func (c *Compiler) compileBlockStatement(stmt *BlockStatement, currentStateID, nextStateID string) (string, error) {
	// Create block state
	stateID := c.generateStateID("block")
	blockState := NewBlockState(stateID, stmt.Name)

	// Compile the block's statements
	blockEndStateID := c.generateStateID("block_end")
	blockEndState := NewInitialState(blockEndStateID) // Just a pass-through state
	c.fsm.AddState(blockEndState)

	// Connect block end to next state
	blockEndState.SetTransitions([]Transition{{TargetState: nextStateID}})

	// Compile the block statements
	_, err := c.compileStatements(stmt.Statements, stateID, blockEndStateID)
	if err != nil {
		return "", fmt.Errorf("failed to compile block statements: %v", err)
	}

	c.fsm.AddState(blockState)

	// Connect current state to this new state
	if currentState, exists := c.fsm.States[currentStateID]; exists {
		transitions := currentState.GetTransitions()
		transitions = append(transitions, Transition{TargetState: stateID})
		currentState.SetTransitions(transitions)
	}

	return nextStateID, nil
}

// compileConditionalStatement compiles a conditional statement
func (c *Compiler) compileConditionalStatement(stmt *ConditionalStatement, currentStateID, nextStateID string) (string, error) {
	// Create conditional state
	stateID := c.generateStateID("conditional")

	// Create states for true and false branches
	trueStateID := c.generateStateID("true_branch")
	falseStateID := c.generateStateID("false_branch")

	// Create the actual true and false branch entry states
	trueBranchState := NewInitialState(trueStateID)
	falseBranchState := NewInitialState(falseStateID)
	c.fsm.AddState(trueBranchState)
	c.fsm.AddState(falseBranchState)

	// Compile true branch - the ThenBlock is a single statement
	trueBranchEndID, err := c.compileStatement(stmt.ThenBlock, trueStateID, nextStateID)
	if err != nil {
		return "", fmt.Errorf("failed to compile true branch: %v", err)
	}

	// Compile false branch (if exists)
	var falseBranchEndID string
	if stmt.ElseBlock != nil {
		falseBranchEndID, err = c.compileStatement(stmt.ElseBlock, falseStateID, nextStateID)
		if err != nil {
			return "", fmt.Errorf("failed to compile false branch: %v", err)
		}
	} else {
		// If no false branch, just connect to next state
		falseBranchState.SetTransitions([]Transition{{TargetState: nextStateID}})
		falseBranchEndID = nextStateID
	}

	// Convert condition statement to string for now
	conditionStr := stmt.Condition.String()
	conditionalState := NewConditionalState(stateID, conditionStr, trueBranchEndID, falseBranchEndID)

	// Set up transitions
	conditionalState.SetTransitions([]Transition{
		{TargetState: trueStateID, Condition: "true"},
		{TargetState: falseStateID, Condition: "false"},
	})

	c.fsm.AddState(conditionalState)

	// Connect current state to this new state
	if currentState, exists := c.fsm.States[currentStateID]; exists {
		transitions := currentState.GetTransitions()
		transitions = append(transitions, Transition{TargetState: stateID})
		currentState.SetTransitions(transitions)
	}

	return nextStateID, nil
}

// compileEllipsisStatement compiles an ellipsis statement
func (c *Compiler) compileEllipsisStatement(stmt *EllipsisStatement, currentStateID, nextStateID string) (string, error) {
	// For now, ellipsis statements just pass through
	// In a more sophisticated implementation, they would handle repetition patterns

	// Connect current state directly to next state
	if currentState, exists := c.fsm.States[currentStateID]; exists {
		transitions := currentState.GetTransitions()
		transitions = append(transitions, Transition{TargetState: nextStateID})
		currentState.SetTransitions(transitions)
	}

	return nextStateID, nil
}

// compileParameter compiles a parameter into a ParameterMatcher
func (c *Compiler) compileParameter(param Parameter) (ParameterMatcher, error) {
	switch param.Operator {
	case AssignOp:
		// Handle string assignment
		switch value := param.Value.(type) {
		case *StringValue:
			return &StringParameterMatcher{
				ParameterName: param.Name,
				ExpectedValue: value.Value,
			}, nil
		case *RegexValue:
			// Even with = operator, if it's a regex value, treat as regex
			regex, err := regexp.Compile(value.Pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex pattern %s: %v", value.Pattern, err)
			}
			return &RegexParameterMatcher{
				ParameterName: param.Name,
				Pattern:       regex,
			}, nil
		default:
			return nil, fmt.Errorf("unsupported parameter value type: %T", param.Value)
		}
	case RegexMatchOp:
		// Handle regex matching
		switch value := param.Value.(type) {
		case *StringValue:
			// Parse as regex pattern
			regex, err := regexp.Compile(value.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid regex pattern %s: %v", value.Value, err)
			}
			return &RegexParameterMatcher{
				ParameterName: param.Name,
				Pattern:       regex,
			}, nil
		case *RegexValue:
			regex, err := regexp.Compile(value.Pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex pattern %s: %v", value.Pattern, err)
			}
			return &RegexParameterMatcher{
				ParameterName: param.Name,
				Pattern:       regex,
			}, nil
		default:
			return nil, fmt.Errorf("unsupported parameter value type for regex: %T", param.Value)
		}
	default:
		return nil, fmt.Errorf("unsupported parameter operator: %v", param.Operator)
	}
}

// generateStateID generates a unique state ID
func (c *Compiler) generateStateID(prefix string) string {
	id := fmt.Sprintf("%s_%d", prefix, c.nextStateID)
	c.nextStateID++
	return id
}

// Helper function to compile a program from source code
func CompileProgram(source string) (*FSM, error) {
	// Tokenize the source
	tokens, err := TokenizeInput(source)
	if err != nil {
		return nil, fmt.Errorf("tokenization failed: %v", err)
	}

	// Parse the tokens
	parser := NewParser(tokens)
	program, err := parser.Parse()
	if err != nil {
		return nil, fmt.Errorf("parsing failed: %v", err)
	}

	// Compile to FSM
	compiler := NewCompiler()
	fsm, err := compiler.Compile(program)
	if err != nil {
		return nil, fmt.Errorf("compilation failed: %v", err)
	}

	return fsm, nil
}
