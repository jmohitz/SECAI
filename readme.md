Based on my analysis of your [SecAI repository](https://github.com/jmohitz/SECAI), I'll create a comprehensive README file that accurately describes your AI-powered security code analysis and fixing tool. Here's a detailed README tailored to your project:

# SecAI

**AI-Powered Security Code Analysis and Fixing Tool**

SecAI is an intelligent security analysis tool that automatically detects and fixes cryptographic vulnerabilities in Java code using Large Language Models (LLMs). The tool leverages CrySL (Cryptographic Specification Language) rules to identify security issues and applies AI-powered fixes to remediate them.

## Overview

SecAI combines static analysis with AI-driven code generation to provide automated security vulnerability remediation. The tool analyzes Java code against cryptographic best practices, identifies violations of CrySL rules, and generates secure code alternatives using various LLM models.

### Key Features

- **Automated Vulnerability Detection**: Uses CrySL rules to identify cryptographic vulnerabilities
- **AI-Powered Code Fixing**: Leverages multiple LLM models (OpenAI, Gemini, etc.) for intelligent code remediation
- **RAG Pipeline**: Implements Retrieval-Augmented Generation for context-aware vulnerability fixing
- **Database Caching**: Stores analysis results to avoid redundant processing
- **RESTful API**: Provides easy integration via Flask-based web API
- **Docker Support**: Containerized deployment for easy scaling
- **CWE Mapping**: Maps Common Weakness Enumeration (CWE) entries to CrySL rules

## Architecture

The project follows a modular architecture with the following core components:

### Core Components

- **`main.py`**: Flask application serving the REST API endpoints
- **`aifix.py`**: Main AI fixing logic with LLM integration
- **`rag_pipeline.py`**: Retrieval-Augmented Generation implementation
- **`ccrun.py`**: CrySL/CogniCrypt integration for static analysis
- **`app_db.py`**: Database operations for caching and persistence
- **`payload_extraction.py`**: Request payload processing and validation

### Supporting Modules

- **`document_processor.py`**: Document parsing and preprocessing
- **`vector_store_manager.py`**: Vector database management for RAG
- **`logger_config.py`**: Centralized logging configuration

## Installation

### Prerequisites

- Python 3.8+
- Java 8+ (for CrySL analysis)
- Docker (optional, for containerized deployment)

### Local Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/jmohitz/SECAI.git
   cd SECAI
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   Configure your LLM API keys:
   ```bash
   export OPENAI_API_KEY="your-openai-key"
   export GOOGLE_API_KEY="your-google-key"  # For Gemini models
   ```

4. **Initialize the database**
   ```bash
   python app_db.py
   ```

### Docker Deployment

```bash
docker build -t secai .
docker run -p 8000:8000 secai
```

## Usage

### API Endpoints

#### `/aifix` - Legacy Single Analysis
Analyzes and fixes a single code snippet:

```bash
curl -X POST http://localhost:8000/aifix \
  -H "Content-Type: application/json" \
  -d '{
    "code": "your_vulnerable_code_here",
    "rule": "cryptographic_rule",
    "msg": "error_message",
    "llm_model": "openai",
    "iterations": 3
  }'
```

#### `/newfix` - Enhanced Analysis Pipeline
Processes complex payloads with multiple vulnerabilities:

```bash
curl -X POST http://localhost:8000/newfix \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilities": [...],
    "context": "...",
    "preferences": {...}
  }'
```

### Supported LLM Models

- **OpenAI**: GPT-3.5, GPT-4 variants
- **Google**: Gemini Pro models
- **Anthropic**: Claude models (configurable)

### Configuration Options

- **Iterations**: Number of fixing attempts (default: 3)
- **Model Selection**: Choose from available LLM providers
- **Temperature**: Control creativity vs precision in fixes
- **Context Window**: Adjust RAG context retrieval size

## Project Structure

```
SECAI/
├── CCJar/                    # CrySL analyzer JAR files
├── CWE_Mapping/             # CWE to CrySL rule mappings
├── GeneratedCode/           # AI-generated fixed code samples
├── JCA-CrySL-rules/        # Java Cryptographic Architecture rules
├── data/                    # Training and reference data
├── faiss_index/            # Vector store indices
├── llm_files/              # LLM configuration and prompts
├── pydantic_models/        # Data validation models
├── utils/                  # Utility functions
├── aifix.py               # Core AI fixing logic
├── ccrun.py               # CrySL analysis runner
├── main.py                # Flask application
├── rag_pipeline.py        # RAG implementation
├── requirements.txt       # Python dependencies
├── Dockerfile            # Container configuration
└── README.md
```

## Development

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Running Tests

```bash
python -m pytest tests/
```

### Code Quality

The project uses:
- **Logging**: Centralized logging configuration
- **Error Handling**: Comprehensive exception management
- **Database Caching**: Result persistence for performance
- **Type Safety**: Pydantic models for data validation

## Research Context

This tool was developed as part of a Master's thesis in Computer Science at the University of Paderborn, focusing on:
- **Explainable AI (XAI)** applications in security
- **CWE-to-CrySL rule mapping** automation
- **LLM-based code remediation** effectiveness
- **RAG pipeline optimization** for security contexts
