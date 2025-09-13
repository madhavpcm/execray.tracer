package policyd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"execray.tracer/internal/compiler"
	"github.com/sirupsen/logrus"
)

// CompiledPolicy represents a compiled policy with its FSM and metadata
type CompiledPolicy struct {
	ID          string
	Name        string
	Description string
	SourceFile  string
	FSM         *compiler.FSM
	Engine      *compiler.ExecutionEngine
	ModTime     time.Time
}

// PolicyLoader handles loading and compiling policy files from a directory
type PolicyLoader struct {
	ConfigPath      string
	policies        map[string]*CompiledPolicy
	mu              sync.RWMutex
	log             *logrus.Logger
	lastScan        time.Time
	watcherInterval time.Duration
}

// NewPolicyLoader creates a new policy loader for the given config path
func NewPolicyLoader(configPath string) *PolicyLoader {
	return &PolicyLoader{
		ConfigPath:      configPath,
		policies:        make(map[string]*CompiledPolicy),
		log:             logrus.New(),
		watcherInterval: 5 * time.Second, // Check for changes every 5 seconds
	}
}

// LoadPolicies scans the config path and loads all .policy files
func (pl *PolicyLoader) LoadPolicies() error {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	pl.log.WithField("path", pl.ConfigPath).Info("Loading policies from directory")

	// Check if config path exists
	if _, err := os.Stat(pl.ConfigPath); os.IsNotExist(err) {
		return fmt.Errorf("config path does not exist: %s", pl.ConfigPath)
	}

	// Clear existing policies
	pl.policies = make(map[string]*CompiledPolicy)

	// Walk through the directory
	err := filepath.WalkDir(pl.ConfigPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-.policy files
		if d.IsDir() || !strings.HasSuffix(path, ".policy") {
			return nil
		}

		// Load and compile the policy file
		if err := pl.loadPolicyFile(path); err != nil {
			pl.log.WithField("file", path).WithError(err).Error("Failed to load policy file")
			// Continue loading other files instead of failing completely
			return nil
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to scan policy directory: %v", err)
	}

	pl.lastScan = time.Now()
	pl.log.WithField("count", len(pl.policies)).Info("Policies loaded successfully")

	return nil
}

// loadPolicyFile loads and compiles a single policy file
func (pl *PolicyLoader) loadPolicyFile(filePath string) error {
	// Read the policy file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %v", err)
	}

	// Get file info for modification time tracking
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}

	// Compile the policy using the FSM compiler
	fsm, err := compiler.CompileProgram(string(content))
	if err != nil {
		return fmt.Errorf("failed to compile policy: %v", err)
	}

	// Create execution engine
	engine := compiler.NewExecutionEngine(fsm)
	if err := engine.ValidateFSM(); err != nil {
		return fmt.Errorf("FSM validation failed: %v", err)
	}

	// Generate policy ID from file name
	fileName := filepath.Base(filePath)
	policyID := strings.TrimSuffix(fileName, ".policy")

	// Create compiled policy
	compiledPolicy := &CompiledPolicy{
		ID:          policyID,
		Name:        policyID, // Can be enhanced to extract from policy content
		Description: fmt.Sprintf("Policy loaded from %s", fileName),
		SourceFile:  filePath,
		FSM:         fsm,
		Engine:      engine,
		ModTime:     fileInfo.ModTime(),
	}

	pl.policies[policyID] = compiledPolicy

	pl.log.WithFields(logrus.Fields{
		"id":     policyID,
		"file":   filePath,
		"states": len(fsm.States),
	}).Info("Policy compiled successfully")

	return nil
}

// GetPolicies returns a copy of all loaded policies
func (pl *PolicyLoader) GetPolicies() map[string]*CompiledPolicy {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	// Return a copy to avoid concurrent access issues
	policies := make(map[string]*CompiledPolicy)
	for id, policy := range pl.policies {
		policies[id] = policy
	}
	return policies
}

// GetPolicy returns a specific policy by ID
func (pl *PolicyLoader) GetPolicy(id string) (*CompiledPolicy, bool) {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	policy, exists := pl.policies[id]
	return policy, exists
}

// CheckForChanges checks if any policy files have been modified and reloads them
func (pl *PolicyLoader) CheckForChanges() error {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	hasChanges := false

	// Check each loaded policy file for modifications
	for id, policy := range pl.policies {
		fileInfo, err := os.Stat(policy.SourceFile)
		if err != nil {
			// File might have been deleted
			pl.log.WithField("file", policy.SourceFile).Warn("Policy file no longer exists, removing")
			delete(pl.policies, id)
			hasChanges = true
			continue
		}

		if fileInfo.ModTime().After(policy.ModTime) {
			pl.log.WithField("file", policy.SourceFile).Info("Policy file modified, reloading")
			if err := pl.loadPolicyFile(policy.SourceFile); err != nil {
				pl.log.WithField("file", policy.SourceFile).WithError(err).Error("Failed to reload policy file")
			} else {
				hasChanges = true
			}
		}
	}

	// Check for new policy files
	err := filepath.WalkDir(pl.ConfigPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".policy") {
			return nil
		}

		// Check if this is a new file
		fileName := filepath.Base(path)
		policyID := strings.TrimSuffix(fileName, ".policy")

		if _, exists := pl.policies[policyID]; !exists {
			pl.log.WithField("file", path).Info("New policy file detected, loading")
			if err := pl.loadPolicyFile(path); err != nil {
				pl.log.WithField("file", path).WithError(err).Error("Failed to load new policy file")
			} else {
				hasChanges = true
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to check for new policy files: %v", err)
	}

	if hasChanges {
		pl.log.Info("Policy changes detected and applied")
	}

	return nil
}

// StartWatcher starts a background goroutine that periodically checks for policy file changes
func (pl *PolicyLoader) StartWatcher() {
	go func() {
		ticker := time.NewTicker(pl.watcherInterval)
		defer ticker.Stop()

		for range ticker.C {
			if err := pl.CheckForChanges(); err != nil {
				pl.log.WithError(err).Error("Failed to check for policy changes")
			}
		}
	}()

	pl.log.WithField("interval", pl.watcherInterval).Info("Policy file watcher started")
}

// Stop stops the policy loader (mainly for cleanup)
func (pl *PolicyLoader) Stop() {
	pl.log.Info("Policy loader stopped")
}
