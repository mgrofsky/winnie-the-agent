"""Write a copy of a CloudFormation template without its YAML comment lines.

    python deploy/aws/strip_comments.py deploy/aws/sensor.yaml sensor.deploy.yaml

``aws cloudformation deploy --template-file`` (and ``--template-body``) takes at most 51,200
bytes, and sensor.yaml with its comments is larger. Only whole comment lines outside block
scalars are dropped; block scalars (the user data scripts, descriptions) are kept byte for
byte, so a ``#`` line inside a script stays. The copy is written only if it parses to the
same document as the original and fits the limit; deploy/aws/check.py runs the same checks.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TEMPLATE_BODY_LIMIT = 51_200          # bytes, CloudFormation's inline template limit
# A line that opens a block scalar: "key: |", "- >-", "!Sub |" and so on.
_BLOCK_START = re.compile(r"(:|-|!\w+)\s+[|>][-+]?\s*$")


def strip(text: str) -> str:
    """``text`` without comment lines, except inside block scalars."""
    out: list[str] = []
    block_parent = None                # indentation of the line that opened a block scalar
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\n")
        indent = len(body) - len(body.lstrip(" "))
        if block_parent is not None:
            if not body.strip() or indent > block_parent:
                out.append(line)
                continue
            block_parent = None
        if body.lstrip().startswith("#"):
            continue
        out.append(line)
        if _BLOCK_START.search(body):
            block_parent = indent
    return "".join(out)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    src, dst = Path(argv[0]), Path(argv[1])
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import check

    raw = src.read_text(encoding="utf-8")
    problems = check.deploy_copy_problems(raw)
    if problems:
        for p in problems:
            print(f"{src}: {p}", file=sys.stderr)
        return 1
    stripped = strip(raw)
    dst.write_text(stripped, encoding="utf-8")
    print(f"{dst}: {len(stripped.encode())} bytes (limit {TEMPLATE_BODY_LIMIT}), "
          f"same document as {src}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
