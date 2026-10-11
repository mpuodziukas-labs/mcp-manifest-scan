#!/usr/bin/env python3
"""Static scanner for MCP server tool manifests. Stdlib only, no network.

Usage: python3 mcp_scan.py PATH [PATH...]   (files or directories of *.json)
Exit 0: no HIGH finding. Exit 1: at least one HIGH. Exit 2: unreadable input.
"""
import json, os, pathlib, re, sys, unicodedata

HIGH, MEDIUM = "HIGH", "MEDIUM"


class ManifestError(Exception):
    pass


def load(path):
    """Return a list of server dicts from one manifest file. Raise ManifestError on any problem."""
    try:
        doc = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ManifestError(f"{path}: unreadable ({type(e).__name__})")
    servers = doc.get("servers") if isinstance(doc, dict) and "servers" in doc else [doc]
    if not isinstance(servers, list) or not servers:
        raise ManifestError(f"{path}: no servers")
    for s in servers:
        if not isinstance(s, dict) or not isinstance(s.get("name"), str):
            raise ManifestError(f"{path}: server needs a string name")
        tools, cfg = s.get("tools", []), s.get("config", {})
        if not isinstance(tools, list) or not isinstance(cfg, dict):
            raise ManifestError(f"{path}: tools must be a list and config an object")
        for t in tools:
            if not isinstance(t, dict) or not isinstance(t.get("name"), str):
                raise ManifestError(f"{path}: tool needs a string name")
            if not isinstance(t.get("inputSchema", {}), dict):
                raise ManifestError(f"{path}: inputSchema must be an object")
        if not isinstance(cfg.get("args", []), list) or not isinstance(cfg.get("env", {}), dict):
            raise ManifestError(f"{path}: config.args must be a list and config.env an object")
    return servers


def F(rule, sev, server, tool, msg):
    return {"rule": rule, "sev": sev, "server": server["name"], "tool": tool, "msg": msg}


def _tokens(s):
    return set(re.split(r"[^a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", s).lower()))


def _args(s):
    return [a for a in s.get("config", {}).get("args", []) if isinstance(a, str)]


def _cmd(s):
    return os.path.basename(str(s.get("config", {}).get("command", ""))).lower()


def _descs(schema):
    if isinstance(schema, dict):
        for k, v in schema.items():
            if k == "description" and isinstance(v, str):
                yield v
            else:
                yield from _descs(v)
    elif isinstance(schema, list):
        for v in schema:
            yield from _descs(v)


def _props(schema):
    p = schema.get("properties", {}) if isinstance(schema, dict) else {}
    return p.items() if isinstance(p, dict) else []


SHELLS = {"sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "pwsh"}
EXEC_TOK = {"exec", "execute", "shell", "bash", "eval", "system", "spawn", "subprocess", "powershell"}
EXEC_DESC = re.compile(r"\b(run|runs|execute|executes|exec)\b.{0,25}\b(shell|command|commands|script|code)\b|arbitrary (command|code)", re.I)


def r_exec(servers):
    for s in servers:
        if _cmd(s) in SHELLS and any(a in ("-c", "/c", "-Command") for a in _args(s)):
            yield F("MCP001", HIGH, s, None, "server starts through a shell wrapper")
        for t in s.get("tools", []):
            tk = _tokens(t["name"])
            if tk & EXEC_TOK or {"run", "command"} <= tk or EXEC_DESC.search(t.get("description", "")):
                yield F("MCP001", HIGH, s, t["name"], "tool can run commands or code")


ROOTS = {"/", "/*", "~", "$home", "${home}", "/etc", "/var", "/root", "/usr", "c:\\", "\\"}
PATH_TOK = {"path", "file", "filename", "filepath", "dir", "directory", "folder"}


def r_fs(servers):
    for s in servers:
        for a in _args(s):
            if a.lower() in ROOTS:
                yield F("MCP002", HIGH, s, None, f"filesystem root granted: {a}")
        for t in s.get("tools", []):
            for pn, ps in _props(t.get("inputSchema", {})):
                if _tokens(pn) & PATH_TOK and isinstance(ps, dict) and ps.get("type") == "string" \
                        and not any(k in ps for k in ("pattern", "enum", "const")):
                    yield F("MCP002", MEDIUM, s, t["name"], f"path parameter '{pn}' has no pattern or enum")


SECRET_KEY = re.compile(r"key|token|secret|passw|pwd|credential|auth", re.I)
SECRET_VAL = re.compile(r"\b(?:sk|ghp|gho|xox[abps]|xapp|AKIA|hf)[-_]?[A-Za-z0-9]{16,}|://[^/\s:@]+:[^/\s@]+@")
ARG_FLAG = re.compile(r"^--?(api[-_]?key|token|password|passwd|secret)(=(.*))?$", re.I)


def _literal(v):
    return isinstance(v, str) and v.strip() != "" and not re.match(r"^(\$|<|\{\{|env:)", v.strip())


def r_secret(servers):
    for s in servers:
        for k, v in s.get("config", {}).get("env", {}).items():
            if _literal(v) and (SECRET_KEY.search(k) or SECRET_VAL.search(v)):
                yield F("MCP003", HIGH, s, None, f"literal secret in env {k}")
        a = _args(s)
        for i, x in enumerate(a):
            m = ARG_FLAG.match(x)
            val = (m.group(3) if m.group(2) else (a[i + 1] if i + 1 < len(a) and not a[i + 1].startswith("-") else None)) if m else None
            if (m and _literal(val)) or SECRET_VAL.search(x):
                yield F("MCP003", HIGH, s, None, "literal secret in args")


HIDDEN = [re.compile(p, re.I) for p in (
    r"ignore (all |any )?(previous|prior|above)", r"disregard (the )?(previous|prior|above|system)",
    r"do not (tell|inform|mention|reveal)( this)?( to)? the user", r"<important>|<system>|\[system\]",
    r"\byou (must|shall)\b", r"\bbefore (using|calling) this tool\b",
    r"\b(first|also) (send|read|upload|forward|include)\b.{0,60}\b(contents|file|key|token|history)\b")]


def r_hidden(servers):
    for s in servers:
        for t in s.get("tools", []):
            texts = [t.get("description", "")] + list(_descs(t.get("inputSchema", {})))
            for x in texts:
                if any(unicodedata.category(c) == "Cf" for c in x):
                    yield F("MCP004", HIGH, s, t["name"], "invisible unicode in description")
                elif any(p.search(x) for p in HIDDEN):
                    yield F("MCP004", HIGH, s, t["name"], "instruction aimed at the model in description")


def r_shadow(servers):
    seen = {}
    for s in servers:
        for t in s.get("tools", []):
            k = t["name"].lower().replace("-", "_")
            if k in seen and seen[k] != s["name"]:
                yield F("MCP005", HIGH, s, t["name"], f"tool name also served by '{seen[k]}'")
            seen.setdefault(k, s["name"])


RISKY = {"write", "delete", "remove", "send", "upload", "transfer", "drop", "exec", "execute", "shell"}


def r_broad(servers):
    for s in servers:
        for t in s.get("tools", []):
            if t.get("inputSchema", {}).get("additionalProperties") is True and _tokens(t["name"]) & RISKY:
                yield F("MCP006", HIGH, s, t["name"], "dangerous tool accepts any extra properties")


def _pinned(spec, sep):
    name = spec[1:] if spec.startswith("@") else spec
    return bool(re.search(sep + r"\d", name)) if sep == "@" else bool(re.search(r"(==|@)\d", name))


def r_unpinned(servers):
    for s in servers:
        c, a = _cmd(s), _args(s)
        if c in ("npx", "bunx", "pnpx", "uvx"):
            sep = "@" if c != "uvx" else "=="
            if c == "uvx" and "--from" in a and a.index("--from") + 1 < len(a):
                spec = a[a.index("--from") + 1]
            else:
                spec = next((x for x in a if not x.startswith("-")), None)
            if spec and not spec.startswith((".", "/")) and not _pinned(spec, sep):
                yield F("MCP007", MEDIUM, s, None, f"package not pinned to a version: {spec}")


RULES = [("MCP001", r_exec), ("MCP002", r_fs), ("MCP003", r_secret), ("MCP004", r_hidden),
         ("MCP005", r_shadow), ("MCP006", r_broad), ("MCP007", r_unpinned)]


def scan_servers(servers):
    out = []
    for _, fn in RULES:
        out.extend(fn(servers))
    return out


def scan_file(path):
    return scan_servers(load(path))


def exit_code(findings):
    return 1 if any(f["sev"] == HIGH for f in findings) else 0


def collect(paths):
    files = []
    for p in map(pathlib.Path, paths):
        if p.is_dir():
            found = sorted(p.rglob("*.json"))
            if not found:
                raise ManifestError(f"{p}: no .json manifests found")
            files += found
        else:
            files.append(p)
    return files


def main(argv):
    if not argv:
        print("usage: mcp_scan.py PATH [PATH...]", file=sys.stderr)
        return 2
    rc = 0
    try:
        files = collect(argv)
    except ManifestError as e:
        print(f"ERROR {e}")
        return 2
    for f in files:
        try:
            fs = scan_file(f)
        except ManifestError as e:
            print(f"ERROR {e}")
            rc = 2
            continue
        for x in fs:
            print(f"  {x['sev']} {x['rule']} server={x['server']} tool={x['tool'] or '-'}: {x['msg']}")
        print(f"{f}: {'FAIL' if exit_code(fs) else 'PASS'} ({len(fs)} findings)")
        if rc == 0:
            rc = exit_code(fs)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
