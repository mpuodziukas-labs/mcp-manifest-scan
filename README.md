# mcp-manifest-scan

AI agents load MCP servers whose tool manifests can hide shell access, wide filesystem scope, leaked secrets, prompt injection and unpinned packages; this scanner flags those in the manifest before the client trusts the server.

## Run it in 60 seconds

```
python3 -m pip install pytest
python3 evaluate.py
python3 -m pytest -q
```

## Results

| bad caught | good passed |
|---|---|
| 1/1 | 1/1 |

## Honesty Statement

Synthetic data. Not production, not client data.

## Limitations

Small synthetic corpus. Replace before drawing conclusions.
