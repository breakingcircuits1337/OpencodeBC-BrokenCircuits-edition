#!/usr/bin/env python3
"""
Mistral 3 Large - Azure OpenAI Client

Usage:
    export MISTRAL_ENDPOINT="https://your-resource.cognitiveservices.azure.com/openai/deployments/Mistral-Large-3/chat/completions?api-version=2024-05-01-preview"
    export AZURE_API_KEY="your-key"
    python models/mistral.py "Your prompt here"
"""

import sys
import os
import json
import requests

AZURE_KEY = os.getenv("AZURE_API_KEY")
AZURE_ENDPOINT = os.getenv("MISTRAL_ENDPOINT")

def call_mistral(prompt: str) -> str:
    if not AZURE_KEY:
        raise ValueError("AZURE_API_KEY environment variable not set")
    if not AZURE_ENDPOINT:
        raise ValueError("MISTRAL_ENDPOINT environment variable not set")

    headers = {
        "Content-Type": "application/json",
        "api-key": AZURE_KEY
    }
    
    payload = {
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 4096,
        "temperature": 0.7
    }
    
    response = requests.post(AZURE_ENDPOINT, headers=headers, json=payload)
    response.raise_for_status()
    
    result = response.json()
    return result["choices"][0]["message"]["content"]

if __name__ == "__main__":
    if len(sys.argv) > 1:
        prompt = " ".join(sys.argv[1:])
    else:
        # Check if stdin has content
        if not sys.stdin.isatty():
            prompt = sys.stdin.read().strip()
        else:
            prompt = ""
    
    if not prompt:
        print("Usage: python models/mistral.py 'your prompt'")
        sys.exit(1)
    
    try:
        result = call_mistral(prompt)
        print(result)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
