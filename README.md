# Evidence-Grounding: Reducing LLM Hallucinations in Automated Pentest Reports

## Overview

This project implements an evidence-grounding validation framework that reduces hallucinations in LLM-generated penetration testing reports by 79% (from 4.2% to 0.9%). The system validates LLM-generated claims against structured Nmap scan data to flag unsupported assertions.

**Key Result**: 89% of reports achieved perfect accuracy (0% unsupported claims) with production-ready performance (<$0.01 cost, <1 minute per report).

## Architecture

```
Nmap XML Scans
      ↓
  Parser → JSON Facts
      ↓
   ┌──┴──────────┐
   ↓             ↓
Baseline      Validated
(Ollama only) (Ollama/Claude + Validator)
   ↓             ↓
   └──────┬──────┘
          ↓
    3-Way Evaluation
```

## Quick Start

### 1. Setup Environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Ollama (https://ollama.ai)
# Pull the model
ollama pull llama3.1:8b
```

### 2. Set Up Claude API (Optional)

```bash
# Create .env file with your Anthropic API key
echo "ANTHROPIC_API_KEY=your_key_here" > .env
```

### 3. Run the Pipeline

```bash
# Parse all Nmap scans
python src/parser.py

# Generate baseline reports (Ollama without validation)
python src/baseline_generator.py

# Generate validated reports (Ollama + validator)
python src/validated_generator.py

# Generate Claude reports (Claude + validator)
python src/claude_generator.py

# Compute 3-way comparison
python src/three_way_evaluator.py
```

Or use the Makefile:

```bash
make all  # Run entire pipeline
```

## Project Structure

```
pentest_report_generator/
├── src/
│   ├── parser.py                 # Extract facts from Nmap XML
│   ├── validator.py              # Evidence-grounding validation
│   ├── baseline_generator.py     # Ollama without validation
│   ├── validated_generator.py    # Ollama with validation
│   ├── claude_generator.py       # Claude with validation
│   ├── evaluator.py              # Compute metrics per system
│   └── three_way_evaluator.py    # Compare all 3 systems
│
├── data/
│   ├── raw_scans/                # 20 Nmap XML files (VulnHub machines)
│   └── DATASET_INFO.md           # Dataset documentation
│
├── requirements.txt              # Python dependencies
├── Makefile                      # Automation commands
└── README.md                     # This file
```

## Core Components

### Parser (`parser.py`)
Extracts structured facts from Nmap XML scans:
- Open ports and protocols
- Service names and versions
- Operating system information

### Validator (`validator.py`)
Evidence-grounding validation with 12 bug fixes across 3 categories:
1. **Output Contamination**: Prevents self-referential validation
2. **Context Awareness**: Distinguishes recommendations from findings
3. **Semantic Matching**: Maps LLM terminology to Nmap naming (dns↔domain, smb↔netbios-ssn)

### Generators
- **Baseline**: Ollama llama3.1:8b (no validation)
- **Validated**: Ollama llama3.1:8b + validator
- **Claude**: Claude Haiku 3.5 + validator

### Evaluator (`three_way_evaluator.py`)
Computes comparative metrics:
- Unsupported claim rate
- Perfect report rate (0% unsupported)
- Statistical significance (t-tests, Cohen's d)

## Results Summary

| System | Unsupported Rate | Perfect Reports | Cost per Report |
|--------|------------------|-----------------|-----------------|
| Baseline | 4.2% | 51% (18/35) | $0.00 |
| Validated-Ollama | 2.0% | 63% (22/35) | $0.00 |
| Validated-Claude | 0.9% | 89% (31/35) | <$0.01 |

**Generalization**: Test set from independent source (HackTheBox) outperformed training set (VulnHub), proving no overfitting.

## Dataset

20 vulnerable machines from VulnHub:
- Metasploitable-2
- Kioptrix series  
- Bob, Chronos, DerpNStink, Devguru
- See [data/DATASET_INFO.md](data/DATASET_INFO.md) for complete list

## Requirements

- Python 3.9+
- Ollama (local LLM)
- Anthropic API key (optional, for Claude comparison)

## Course Information

**Course**: CYSE 689 - AI Methods for Cybersecurity  
**Institution**: George Mason University  
**Semester**: Fall 2025  
**Author**: Jake Rockwell

## Citation

If you use this code, please cite the accompanying paper:
*Evidence-Grounding: A Systematic Approach to Reducing LLM Hallucinations in Automated Penetration Testing Reports*

## License

Educational use only.
