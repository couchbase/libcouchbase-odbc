#!/usr/bin/env python3
"""PreToolUse hook: block `git commit` when any message line exceeds 72 chars."""
import json
import re
import shlex
import sys

MAX = 72


def messages(cmd):
    heredocs = re.findall(r"<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n(.*?)\n\s*\1\s*(?:\n|$)", cmd, re.S)
    if heredocs:
        return [body for _, body in heredocs]
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return []
    out = []
    for i, t in enumerate(toks):
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        if t in ("-m", "--message") and nxt is not None:
            out.append(nxt)
        elif t.startswith("--message="):
            out.append(t.split("=", 1)[1])
        elif t.startswith("-m") and len(t) > 2 and not t.startswith("--"):
            out.append(t[2:])
        elif t in ("-F", "--file") and nxt not in (None, "-"):
            try:
                with open(nxt) as f:
                    out.append(f.read())
            except OSError:
                pass
    return out


def main():
    cmd = json.load(sys.stdin).get("tool_input", {}).get("command", "")
    if not re.search(r"\bgit\b[^\n|;&]*\bcommit\b", cmd):
        return 0
    long_lines = [l for m in messages(cmd) for l in m.splitlines() if len(l) > MAX]
    if not long_lines:
        return 0
    print(f"Commit blocked: message lines must be <= {MAX} chars. Rewrap these:", file=sys.stderr)
    for l in long_lines:
        print(f"  ({len(l)}) {l}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
