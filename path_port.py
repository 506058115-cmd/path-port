#!/usr/bin/env python3
"""Find common Windows filename hazards in a local directory tree."""

import argparse
import json
import os
from pathlib import Path
import sys
import unicodedata


INVALID = set('<>:"/\\|?*')
DEVICES = {"CON", "PRN", "AUX", "NUL"}
DEVICES.update(f"COM{digit}" for digit in "123456789¹²³")
DEVICES.update(f"LPT{digit}" for digit in "123456789¹²³")


def quote(value):
    return json.dumps(str(value), ensure_ascii=True)


def component_findings(name):
    problems = []
    if any(char in INVALID or ord(char) < 32 for char in name):
        problems.append("windows-invalid-character")
    if name.endswith((" ", ".")):
        problems.append("trailing-space-or-dot")
    device = name.split(".", 1)[0].rstrip(" .").upper()
    if device in DEVICES:
        problems.append("reserved-device-name")
    return problems


def check_directory(root, findings, errors):
    def walk_error(error):
        errors.append(error)

    for current, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        entries = sorted(dirs + files)
        first_by_key = {}
        for name in entries:
            path = Path(current) / name
            relative = path.relative_to(root)
            for problem in component_findings(name):
                findings.append((problem, relative.as_posix()))
            key = unicodedata.normalize("NFC", name).casefold()
            previous = first_by_key.setdefault(key, name)
            if previous != name:
                kind = "case-collision" if previous.casefold() == name.casefold() else "unicode-normalization-collision"
                findings.append((kind, f"{relative.parent.as_posix()}/{previous} <> {name}"))
        dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check local file and directory names for common Windows portability hazards."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="files or directories to inspect")
    args = parser.parse_args(argv)

    findings = []
    errors = 0
    for root in args.paths:
        if not root.exists():
            print(f"path-port: path not found: {quote(root)}", file=sys.stderr)
            errors += 1
            continue
        if root.is_symlink():
            continue
        if root.is_file():
            for problem in component_findings(root.name):
                findings.append((problem, root.name))
        elif root.is_dir():
            local = []
            walk_errors = []
            check_directory(root, local, walk_errors)
            for problem, path in local:
                findings.append((problem, f"{root}: {path}"))
            for error in walk_errors:
                print(f"path-port: cannot read {quote(error.filename or root)}: {error.strerror}", file=sys.stderr)
                errors += 1
        else:
            print(f"path-port: not a regular file or directory: {quote(root)}", file=sys.stderr)
            errors += 1

    for problem, path in findings:
        print(f"{quote(path)}: {problem}")
    if not findings and not errors:
        print("No common Windows filename hazards found.")
    print(f"{len(findings)} finding(s).", file=sys.stderr)
    return 2 if errors else 1 if findings else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("path-port: interrupted", file=sys.stderr)
        raise SystemExit(130)
