# safe-pip v1.1.0

AI-powered Python package security scanner.

## Install

```
pip install -e .
```

## Usage

```
safe-pip scan requests
safe-pip scan flask --json
safe-pip scan pycrypto --fail-on warn
```

## Features

- PyPI metadata analysis
- Typosquat detection (Levenshtein similarity)
- Known dangerous package database
- Claude AI scoring (set `ANTHROPIC_API_KEY`)
- Local rule-based scoring (no API key needed)

## Known Issues (fixed in v1.2)

- Requires `requests` at runtime — cannot scan `requests` itself without circular dependency
- No scan cache — every scan hits the network
