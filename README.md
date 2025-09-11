# Malware Detection System

**Disclaimer**: This repository involves malware analysis tools and techniques. Exercise extreme caution and use proper isolation when handling suspicious files. The authors are not responsible for any misuse or damage.

A machine learning-based malware detection system that integrates reverse engineering techniques with advanced classification algorithms. This project combines static analysis using industry-standard tools with machine learning models to provide comprehensive malware detection capabilities.

## System Architecture

This system implements a hybrid detection approach that leverages:

- **Static Analysis**: Reverse engineering using Ghidra for binary analysis
- **Signature Detection**: YARA rules for pattern matching and malware family identification
- **Machine Learning**: Trained ensemble models for classification and risk assessment
- **Multi-format Support**: Analysis of various executable formats and archives

## Project Structure

```
malware_detection/
├── config.json          # Tool configuration (Ghidra, YARA paths)
├── model.pkl            # Pre-trained ML model (71KB)
├── results.json         # Analysis results and test data
├── dataset/             # Training datasets and sample files
├── src/                 # Source code modules
├── .gitignore          # Git ignore patterns
└── README.md           # Project documentation
```

## Core Technologies

### Reverse Engineering Tools

**Ghidra Integration**
- NSA's Software Reverse Engineering (SRE) framework
- Automated disassembly and decompilation of executables
- Static code analysis and control flow examination
- API call extraction and behavioral pattern analysis

**YARA Rule Engine**
- Pattern matching for malware signature detection
- Custom rules for malware family classification
- String and hexadecimal pattern identification
- Behavioral signature matching

### Machine Learning Pipeline

**Feature Extraction**
- Static analysis features from Ghidra output
- File structure characteristics (PE headers, sections)
- API call sequences and import table analysis
- String patterns and entropy calculations

**Classification Model**
- Ensemble learning approach for improved accuracy
- Risk scoring system (0-100 scale)
- Binary classification (malware/benign)
- Confidence scoring for predictions

## Configuration

The system is configured through `config.json`:

```json
{
  "tools": {
    "ghidra": {"path": "/opt/ghidra/ghidra_11.3.2_PUBLIC"},
    "yara": {"rules_path": "/home/lewis/yara_rules"}
  }
}
```

### Prerequisites

- **Python 3.8+**: Core runtime environment
- **Ghidra 11.3.2**: Static analysis and reverse engineering
- **YARA**: Pattern matching engine
- **Java 11+**: Required for Ghidra operation

## Installation

### System Setup

1. **Install Ghidra**:
```bash
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20240709.zip
unzip ghidra_11.3.2_PUBLIC_20240709.zip
sudo mv ghidra_11.3.2_PUBLIC /opt/ghidra/
```

2. **Install YARA**:
```bash
sudo apt-get install yara
pip install yara-python
```

3. **Clone and setup project**:
```bash
git clone https://github.com/lewisMVP/malware_detection.git
cd malware_detection
pip install -r requirements.txt
```

4. **Configure paths** in `config.json` to match your system

## Usage Examples

### Basic Analysis

```python
from src.malware_detector import MalwareDetector

# Initialize detector
detector = MalwareDetector()

# Analyze single file
result = detector.analyze_file("sample.exe")
print(f"Risk Score: {result['risk_score']}")
print(f"Classification: {result['classification']}")
```

### Batch Processing

```python
# Analyze multiple files
files = ["sample1.exe", "sample2.dll", "archive.zip"]
results = detector.batch_analyze(files)

for file, result in results.items():
    print(f"{file}: {result['classification']} (Score: {result['risk_score']})")
```

## Analysis Pipeline

### 1. Static Analysis Phase
- **File Parsing**: Ghidra analyzes binary structure
- **Disassembly**: Convert machine code to assembly
- **Feature Extraction**: Extract relevant characteristics:
  - API call sequences
  - Import/export tables
  - String patterns
  - File entropy
  - Control flow graphs

### 2. Signature Matching
- **YARA Scanning**: Apply pattern matching rules
- **Malware Family Detection**: Identify known signatures
- **Behavioral Analysis**: Detect suspicious patterns

### 3. Machine Learning Classification
- **Feature Processing**: Normalize extracted features
- **Model Prediction**: Apply trained ensemble model
- **Risk Assessment**: Generate confidence scores
- **Final Classification**: Combine all analysis results

## Current Test Results

Based on `results.json`, the system has been tested with sample files:

| File | Type | Risk Score | Classification | ML Prediction |
|------|------|------------|---------------|------------|
| sample1.exe | PE32 | 10 | BENIGN | 1 |
| sample2.exe | PE32 | 40 | BENIGN | 1 |
| sample2.zip | Archive | 25 | BENIGN | 1 |
| ls.bin | ELF | 0 | BENIGN | 0 |
| index.html | Web | 0 | BENIGN | 1 |

### Performance Metrics
- **Detection Speed**: < 3 seconds per file
- **Supported Formats**: PE, ELF, ZIP, HTML
- **Risk Scoring**: 0-100 scale assessment
- **Classification Accuracy**: Under evaluation

## Supported File Types

### Executables
- **Windows PE**: .exe, .dll, .sys, .scr
- **Linux ELF**: Binary executables and shared libraries
- **Scripts**: Various scripting formats

### Archives
- **ZIP**: Standard and compressed archives
- **TAR/GZ**: Unix archive formats

### Other Formats
- **HTML**: Web-based content analysis
- **Binary**: Generic binary file analysis

## Development

### Adding New Features

**Custom YARA Rules**:
```bash
# Add rules to configured directory
echo 'rule CustomMalware { strings: $a = "suspicious_string" condition: $a }' > /home/lewis/yara_rules/custom.yar
```

**Model Retraining**:
```python
from src.model_trainer import ModelTrainer

trainer = ModelTrainer()
trainer.retrain_model(new_dataset_path="dataset/updated/")
trainer.save_model("model.pkl")
```

### Testing
```bash
# Run analysis on test samples
python src/main.py --test-mode --sample-dir dataset/
```

## Security Considerations

### Safe Analysis Environment
- Use isolated virtual machines for malware analysis
- Disconnect from network during analysis
- Take VM snapshots before testing suspicious files
- Monitor system resources during analysis

### Best Practices
- Never execute malware samples on production systems
- Use sandbox environments for dynamic analysis
- Keep analysis tools and signatures updated
- Follow responsible disclosure for security research

## Limitations

- **Packed Malware**: May require additional unpacking
- **Polymorphic Threats**: Advanced metamorphic malware challenges
- **Large Files**: Files >100MB may require extended analysis time
- **False Positives**: Legitimate software with suspicious patterns

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with appropriate tests
4. Update documentation
5. Submit a pull request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run code quality checks
python -m pytest tests/
python -m black src/
python -m flake8 src/
```

## Troubleshooting

### Common Issues

**Ghidra Path Error**:
- Verify Ghidra installation path in `config.json`
- Ensure Java 11+ is installed and configured

**YARA Rules Not Found**:
- Check YARA rules directory exists and is readable
- Verify rule syntax is valid

**Model Loading Failed**:
- Ensure `model.pkl` is present in project root
- Check Python package versions compatibility

## Research Applications

This system can be used for:
- Academic malware research
- Cybersecurity education and training
- Threat intelligence development
- Security tool evaluation
- Reverse engineering methodology research

## Legal and Ethical Use

**Important**: This tool is designed for educational and research purposes only. Users must:
- Comply with applicable laws and regulations
- Use appropriate security measures when handling malware
- Follow ethical guidelines for cybersecurity research
- Never use for malicious purposes

## Contact

**Author**: [@lewisMVP](https://github.com/lewisMVP)  
**Repository**: [malware_detection](https://github.com/lewisMVP/malware_detection)

For questions or issues, please open a GitHub issue or contact through the repository.
