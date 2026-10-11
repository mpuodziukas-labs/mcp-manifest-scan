# mcp-manifest-scan

Proves: MCP server security review: static manifest scan with a threat model and planted unsafe manifests. Verify in 60s: `python3 evaluate.py`.

AI agents load MCP servers whose tool manifests can hide shell access, wide filesystem scope, leaked secrets, prompt injection and unpinned packages. This scanner flags those in the manifest, before the client trusts the server.

Python 3 standard library only. No network. No MCP server is started or contacted.

## Run it in 60 seconds

```
python3 -m pip install pytest
python3 evaluate.py
python3 -m pytest -q
python3 mcp_scan.py fixtures/bad_15_combo.json
```

`evaluate.py` scans all fixtures and prints one verdict per fixture. It exits 1 on any mismatch.

## Rules

| ID | Severity | Flags |
|---|---|---|
| MCP001 | HIGH | Tool or server start can run shell commands or code |
| MCP002 | HIGH / MEDIUM | Filesystem root in server args (HIGH); path parameter with no pattern or enum (MEDIUM) |
| MCP003 | HIGH | Literal secret in env or args |
| MCP004 | HIGH | Invisible unicode or model-directed instructions in a description |
| MCP005 | HIGH | Same tool name served by two servers |
| MCP006 | HIGH | `additionalProperties: true` on a write, delete, send or exec tool |
| MCP007 | MEDIUM | `npx`, `uvx` or `bunx` package with no pinned version |

Exit codes of `mcp_scan.py`: 0 no HIGH finding, 1 at least one HIGH finding, 2 unreadable or malformed input (fails closed).

## Results

| fixture | expected | got | exit | verdict |
|---|---|---|---|---|
| bad_01_shell_tool.json | MCP001 | MCP001 | 1 | ok |
| bad_02_shell_wrapper.json | MCP001 | MCP001 | 1 | ok |
| bad_03_fs_schema_unconstrained.json | MCP002 | MCP002 | 0 | ok |
| bad_04_fs_root_arg.json | MCP002 | MCP002 | 1 | ok |
| bad_05_secret_env.json | MCP003 | MCP003 | 1 | ok |
| bad_06_secret_arg.json | MCP003 | MCP003 | 1 | ok |
| bad_07_hidden_ignore.json | MCP004 | MCP004 | 1 | ok |
| bad_08_hidden_unicode.json | MCP004 | MCP004 | 1 | ok |
| bad_09_hidden_imperative.json | MCP004 | MCP004 | 1 | ok |
| bad_10_shadow_names.json | MCP005 | MCP005 | 1 | ok |
| bad_11_broad_schema.json | MCP006 | MCP006 | 1 | ok |
| bad_12_unpinned_npx.json | MCP007 | MCP007 | 0 | ok |
| bad_13_latest_tag.json | MCP007 | MCP007 | 0 | ok |
| bad_14_unpinned_uvx.json | MCP007 | MCP007 | 0 | ok |
| bad_15_combo.json | MCP001,MCP003,MCP007 | MCP001,MCP003,MCP007 | 1 | ok |
| clean_01_scoped_fs.json | - | - | 0 | ok |
| clean_02_search.json | - | - | 0 | ok |
| clean_03_two_servers.json | - | - | 0 | ok |
| clean_04_uvx_pinned.json | - | - | 0 | ok |

caught 15/15 bad, clean passed 4/4

## Honesty Statement

Static scan of manifest JSON only. All 19 fixtures are synthetic and written for this repo. No real server was scanned. Secret-like values in fixtures are made-up strings.

## Limitations

- Reads declared metadata. It cannot see what a server does at runtime, what a tool returns, or a description that changes after the scan.
- Description checks are pattern based. A paraphrased injection passes. A benign description that matches a pattern is flagged.
- MCP007 only checks that a version is present. It does not check a lockfile or a hash.
- Fixtures show each rule fires. They do not measure a false positive rate on real manifests.
- See THREAT-MODEL.md for the full list of blind spots.
