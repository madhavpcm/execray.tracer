# Makefile for building all Go applications in cmd/*

# --- Configuration ---

# Get the name of every directory in cmd/*
# This will result in a list like "app1 app2 app3"
TARGETS := $(notdir $(wildcard cmd/*))

# Define the output directory for our compiled binaries
OUTPUT_DIR := bin

# Create a list of full binary paths, e.g., "bin/app1 bin/app2"
BINS := $(patsubst %,$(OUTPUT_DIR)/%,$(TARGETS))

# Recursively find all Go source files in shared directories.
# The `2>/dev/null` suppresses errors if a directory doesn't exist.
SHARED_SOURCES := $(shell find internal pkg -name '*.go' 2>/dev/null)


# --- Build Targets ---

# The 'all' target is the default. Running 'make' or 'make all' will trigger this.
.PHONY: all
all: $(BINS)

# This is the pattern rule that tells Make how to build any binary.
# It now depends on its own source files AND all shared source files.
$(OUTPUT_DIR)/%: $(wildcard ./cmd/$(*)/*.go) $(SHARED_SOURCES)
	@echo "--> Building $(@)..."
	@mkdir -p $(OUTPUT_DIR) # Create bin directory if it doesn't exist
	@go build -v -o $(@) ./cmd/$(*)

# The 'clean' target is for cleaning up build artifacts.
.PHONY: clean
clean:
	@echo "--> Cleaning up build artifacts..."
	@rm -rf $(OUTPUT_DIR)

# The 'run' target lets you easily run one of the applications.
# Example usage: make run app=app1
.PHONY: run
run:
	@go run ./cmd/$(app)