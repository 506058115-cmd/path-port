# path-port

Find common Windows filename hazards in a local directory tree, useful before copying or packaging files created on Linux. It reads names only; file contents are never opened or changed.

## Use

Requires Python 3.8+; no packages to install.

```sh
python path_port.py .
python path_port.py src assets
```

It reports Windows-reserved characters and device names, names ending in a space or period, and sibling names that collide after NFC normalization and case folding. Findings show quoted paths so control characters cannot act as terminal escape sequences. Symlinks are skipped and are never followed.

The common Windows naming rules are based on [Microsoft's filename guidance](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).

Exit status is `0` when no likely hazards are found, `1` when names need review, and `2` when a requested path is missing or a directory cannot be read. The collision check is a portability heuristic: Windows filesystems and APIs differ in their exact behavior, and path-length or filesystem-specific limits are not checked.

## License

MIT
