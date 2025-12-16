.PHONY: help setup clean parse baseline validated claude evaluate-three all status

# Default target
.DEFAULT_GOAL := help

# Python virtual environment
VENV := venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

# Project directories
SRC := src
DATA := data
RAW_SCANS := $(DATA)/raw_scans
OUTPUT_DIR := output

# Colors
COLOR_RESET := \033[0m
COLOR_GREEN := \033[32m
COLOR_BLUE := \033[34m
COLOR_YELLOW := \033[33m

help: ## Display available commands
	@echo "$(COLOR_BLUE)┌────────────────────────────────────────────────────┐$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)│  Evidence-Grounding Validator - Makefile          │$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)└────────────────────────────────────────────────────┘$(COLOR_RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(COLOR_GREEN)%-18s$(COLOR_RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""

##@ Setup

setup: $(VENV)/bin/activate ## Create virtual environment and install dependencies
	@echo "$(COLOR_GREEN)[SUCCESS] Environment ready$(COLOR_RESET)"
	@echo "To activate: source $(VENV)/bin/activate"

$(VENV)/bin/activate: requirements.txt
	@echo "$(COLOR_BLUE)Creating virtual environment...$(COLOR_RESET)"
	@python3 -m venv $(VENV)
	@$(PIP) install --upgrade pip
	@$(PIP) install -r requirements.txt
	@touch $(VENV)/bin/activate

##@ Data Processing

download-scans: ## Download additional Nmap scans from Vulnerable-Box-Resources (optional)
	@echo "$(COLOR_BLUE)Downloading Vulnerable-Box-Resources...$(COLOR_RESET)"
	@if [ ! -d "Vulnerable-Box-Resources" ]; then \
		echo "$(COLOR_YELLOW)Cloning repository...$(COLOR_RESET)"; \
		git clone https://github.com/InfoSecWarrior/Vulnerable-Box-Resources.git; \
		echo "$(COLOR_GREEN)[SUCCESS] Downloaded additional scan resources$(COLOR_RESET)"; \
		echo "$(COLOR_BLUE)Available in: Vulnerable-Box-Resources/$(COLOR_RESET)"; \
		echo "$(COLOR_YELLOW)Note: Our 20 included scans are sufficient for reproducing results$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)Vulnerable-Box-Resources already exists$(COLOR_RESET)"; \
	fi

parse: ## Parse Nmap XML scans to JSON facts
	@echo "$(COLOR_BLUE)Parsing Nmap XML files...$(COLOR_RESET)"
	@mkdir -p $(OUTPUT_DIR)/parsed_facts
	@$(PYTHON) $(SRC)/parser.py --input $(RAW_SCANS) --output $(OUTPUT_DIR)/parsed_facts
	@echo "$(COLOR_GREEN)[SUCCESS] Parsed $(shell ls -1 $(RAW_SCANS)/*.xml | wc -l | xargs) scans$(COLOR_RESET)"

##@ Report Generation

baseline: parse ## Generate baseline reports (Ollama without validation)
	@echo "$(COLOR_BLUE)Generating baseline reports...$(COLOR_RESET)"
	@mkdir -p $(OUTPUT_DIR)/reports/baseline $(OUTPUT_DIR)/metrics/baseline
	@$(PYTHON) $(SRC)/baseline_generator.py --facts $(OUTPUT_DIR)/parsed_facts --output $(OUTPUT_DIR)/reports/baseline
	@echo "$(COLOR_GREEN)[SUCCESS] Baseline reports generated$(COLOR_RESET)"

validated: parse ## Generate validated reports (Ollama + validator)
	@echo "$(COLOR_BLUE)Generating validated reports...$(COLOR_RESET)"
	@mkdir -p $(OUTPUT_DIR)/reports/validated $(OUTPUT_DIR)/metrics/validated
	@$(PYTHON) $(SRC)/validated_generator.py --facts $(OUTPUT_DIR)/parsed_facts --output $(OUTPUT_DIR)/reports/validated
	@echo "$(COLOR_GREEN)[SUCCESS] Validated reports generated$(COLOR_RESET)"

claude: parse ## Generate Claude reports (Claude + validator)
	@echo "$(COLOR_BLUE)Generating Claude reports...$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Note: Requires ANTHROPIC_API_KEY in .env$(COLOR_RESET)"
	@mkdir -p $(OUTPUT_DIR)/reports/claude $(OUTPUT_DIR)/metrics/claude
	@$(PYTHON) $(SRC)/claude_generator.py --facts $(OUTPUT_DIR)/parsed_facts --output $(OUTPUT_DIR)/reports/claude
	@echo "$(COLOR_GREEN)[SUCCESS] Claude reports generated$(COLOR_RESET)"

##@ Evaluation

evaluate-three: baseline validated claude ## Run 3-way comparison (Baseline vs Validated vs Claude)
	@echo "$(COLOR_BLUE)Computing 3-way comparison...$(COLOR_RESET)"
	@mkdir -p $(OUTPUT_DIR)/metrics
	@$(PYTHON) $(SRC)/three_way_evaluator.py --baseline $(OUTPUT_DIR)/reports/baseline --validated $(OUTPUT_DIR)/reports/validated --claude $(OUTPUT_DIR)/reports/claude --output $(OUTPUT_DIR)/metrics
	@echo "$(COLOR_GREEN)[SUCCESS] Evaluation complete$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BLUE)Results saved to: $(OUTPUT_DIR)/metrics/$(COLOR_RESET)"

##@ Full Pipeline

all: setup parse baseline validated claude evaluate-three ## Run complete pipeline
	@echo ""
	@echo "$(COLOR_GREEN)======================================================$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)  [SUCCESS] Complete pipeline finished$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)======================================================$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BLUE)Check output in: $(OUTPUT_DIR)/$(COLOR_RESET)"

quick: setup parse baseline validated ## Quick run (skip Claude to save cost)
	@echo "$(COLOR_BLUE)Running quick comparison (Baseline vs Validated)...$(COLOR_RESET)"
	@mkdir -p $(OUTPUT_DIR)/metrics
	@$(PYTHON) $(SRC)/evaluator.py --baseline $(OUTPUT_DIR)/reports/baseline --validated $(OUTPUT_DIR)/reports/validated --output $(OUTPUT_DIR)/metrics
	@echo "$(COLOR_GREEN)[SUCCESS] Quick evaluation complete$(COLOR_RESET)"

##@ Utilities

status: ## Show project status
	@echo "$(COLOR_BLUE)Project Status:$(COLOR_RESET)"
	@echo ""
	@echo "Raw Scans:    $(shell ls -1 $(RAW_SCANS)/*.xml 2>/dev/null | wc -l | xargs) files"
	@if [ -d $(OUTPUT_DIR)/parsed_facts ]; then \
		echo "Parsed Facts: $(shell ls -1 $(OUTPUT_DIR)/parsed_facts/*.json 2>/dev/null | wc -l | xargs) files"; \
	else \
		echo "Parsed Facts: 0 files (run 'make parse')"; \
	fi
	@echo ""
	@if [ -d $(VENV) ]; then \
		echo "$(COLOR_GREEN)[OK] Virtual environment exists$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)[WARN] Run 'make setup' first$(COLOR_RESET)"; \
	fi
	@if pgrep -x "ollama" > /dev/null 2>&1; then \
		echo "$(COLOR_GREEN)[OK] Ollama running$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)[WARN] Ollama not running (needed for baseline & validated)$(COLOR_RESET)"; \
	fi
	@if [ -f .env ] && grep -q ANTHROPIC_API_KEY .env 2>/dev/null; then \
		echo "$(COLOR_GREEN)[OK] Claude API key configured$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)[INFO] Claude API key not found (optional, for claude target)$(COLOR_RESET)"; \
	fi

clean: ## Remove generated output files
	@echo "$(COLOR_YELLOW)Cleaning generated files...$(COLOR_RESET)"
	@rm -rf $(OUTPUT_DIR)
	@echo "$(COLOR_GREEN)[SUCCESS] Cleaned$(COLOR_RESET)"

clean-all: clean ## Remove output and virtual environment
	@echo "$(COLOR_YELLOW)Removing virtual environment...$(COLOR_RESET)"
	@rm -rf $(VENV)
	@echo "$(COLOR_GREEN)[SUCCESS] Complete reset$(COLOR_RESET)"

##@ Ollama

ollama-check: ## Check Ollama status and model
	@if pgrep -x "ollama" > /dev/null 2>&1; then \
		echo "$(COLOR_GREEN)[OK] Ollama is running$(COLOR_RESET)"; \
		echo ""; \
		echo "Available models:"; \
		ollama list 2>/dev/null || echo "  (could not list models)"; \
	else \
		echo "$(COLOR_YELLOW)[WARN] Ollama is not running$(COLOR_RESET)"; \
		echo ""; \
		echo "To start Ollama:"; \
		echo "  1. Install from https://ollama.ai"; \
		echo "  2. Run: ollama serve"; \
		echo "  3. Pull model: ollama pull llama3.1:8b"; \
	fi

##@ Info

version: ## Show version info
	@echo "$(COLOR_BLUE)Evidence-Grounding Validator$(COLOR_RESET)"
	@echo "Version: 1.0.0 (Final Submission)"
	@if [ -d $(VENV) ]; then \
		echo "Python: $(shell $(PYTHON) --version)"; \
	else \
		echo "Python: $(shell python3 --version)"; \
	fi
	@echo "Ollama: $(shell ollama --version 2>/dev/null || echo 'Not installed')"
