# AI Models

This directory contains scripts to call Azure AI models directly.

## Models Available

### Mistral Large 3
- **File**: `mistral.py`
- **Description**: Large language model optimized for reasoning and code
- **Usage**:
  ```bash
  python models/mistral.py "Write a hello world in Python"
  echo "Your prompt" | python models/mistral.py
  ```

### Kimi K2 Thinking
- **File**: `kimi.py`
- **Description**: Advanced thinking model for complex reasoning
- **Usage**:
  ```bash
  python models/kimi.py "Explain quantum computing"
  echo "Your prompt" | python models/kimi.py
  ```

## Setup

The scripts use environment variables from `.env`:
- `AZURE_API_KEY`
- `MISTRAL_ENDPOINT` (for Mistral)
- `KIMI_ENDPOINT` (for Kimi)

Make sure your `.env` file is configured before running.
