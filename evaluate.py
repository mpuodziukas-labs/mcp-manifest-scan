"""Run the scanner over every fixture and compare with the expected rule set. Exit 1 on any mismatch."""
import pathlib, sys
import mcp_scan

FIX = pathlib.Path(__file__).with_name("fixtures")
# fixture -> exact rule IDs it must trip (empty = clean)
EXPECTED = {
    "clean_01_scoped_fs.json": [], "clean_02_search.json": [], "clean_03_two_servers.json": [],
    "clean_04_uvx_pinned.json": [],
    "bad_01_shell_tool.json": ["MCP001"], "bad_02_shell_wrapper.json": ["MCP001"],
    "bad_03_fs_schema_unconstrained.json": ["MCP002"], "bad_04_fs_root_arg.json": ["MCP002"],
    "bad_05_secret_env.json": ["MCP003"], "bad_06_secret_arg.json": ["MCP003"],
    "bad_07_hidden_ignore.json": ["MCP004"], "bad_08_hidden_unicode.json": ["MCP004"],
    "bad_09_hidden_imperative.json": ["MCP004"], "bad_10_shadow_names.json": ["MCP005"],
    "bad_11_broad_schema.json": ["MCP006"], "bad_12_unpinned_npx.json": ["MCP007"],
    "bad_13_latest_tag.json": ["MCP007"], "bad_14_unpinned_uvx.json": ["MCP007"],
    "bad_15_combo.json": ["MCP001", "MCP003", "MCP007"],
}


def rows():
    out = []
    for name in sorted(EXPECTED):
        fs = mcp_scan.scan_file(FIX / name)
        got = sorted({f["rule"] for f in fs})
        out.append((name, EXPECTED[name], got, mcp_scan.exit_code(fs)))
    return out


def results():
    r = rows()
    lines = ["| fixture | expected | got | exit | verdict |", "|---|---|---|---|---|"]
    for name, exp, got, rc in r:
        lines.append(f"| {name} | {','.join(exp) or '-'} | {','.join(got) or '-'} | {rc} | {'ok' if exp == got else 'MISS'} |")
    bad = [x for x in r if x[1]]
    caught = sum(1 for x in bad if x[1] == x[2])
    clean = [x for x in r if not x[1]]
    passed = sum(1 for x in clean if not x[2] and x[3] == 0)
    lines.append("")
    lines.append(f"caught {caught}/{len(bad)} bad, clean passed {passed}/{len(clean)}")
    return "\n".join(lines)


def main():
    print(results())
    return 0 if all(e == g for _, e, g, _ in rows()) else 1


if __name__ == "__main__":
    sys.exit(main())
