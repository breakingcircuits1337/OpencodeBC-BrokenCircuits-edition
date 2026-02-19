#!/usr/bin/env python3
"""
Azure LLM Bridge - Call Kimi K2 Thinking via Azure OpenAI

Usage:
    python kimi.py "Your prompt here"
    echo "Your prompt" | python kimi.py
    
Environment Variables:
    AZURE_API_KEY - Your Azure API key
    KIMI_ENDPOINT - Azure endpoint for Kimi (optional, uses default)
"""

import sys
import os
import requests

# Configuration
AZURE_KEY = os.getenv("AZURE_API_KEY")
AZURE_ENDPOINT = os.getenv(
    "KIMI_ENDPOINT",
    "https://brokencircuits-1334-resource.cognitiveservices.azure.com/openai/deployments/Kimi-K2-Thinking/chat/completions?api-version=2024-05-01-preview"
)

def call_kimi(prompt: str, max_tokens: int = 4096, temperature: float = 0.7) -> str:
    """Call Kimi K2 Thinking via Azure OpenAI."""
    
    if not AZURE_KEY:
        raise ValueError("AZURE_API_KEY environment variable not set")
    
    headers = {
        "Content-Type": "application/json",
        "api-key": AZURE_KEY
    }
    
    payload = {
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": temperature
    }
    
    response = requests.post(AZURE_ENDPOINT, headers=headers, json=payload)
    response.raise_for_status()
    
    result = response.json()
    return result["choices"][0]["message"]["content"]

if __name__ == "__main__":
    # Get prompt from command line or stdin
    if len(sys.argv) > 1:
        prompt = " ".join(sys.argv[1:])
    else:
        prompt = sys.stdin.read().strip()
    
    if not prompt:
        print("Usage: python kimi.py 'Your prompt here'")
        print("   or: echo 'Your prompt' | python kimi.py")
        sys.exit(1)
    
    try:
        result = call_kimi(prompt)
        print(result)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
