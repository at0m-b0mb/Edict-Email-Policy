"""
``python -m edict`` — open the window; with an argument, run the CLI.

A bare invocation launches the graphical grader. Anything on the command line
(a file of records, ``-`` for a pipe, or a flag) is handed to the command-line
interface instead, so the same module serves both.
"""

from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) > 1:
        from .cli import main as cli_main
        return cli_main(sys.argv[1:])
    from .app import main as app_main
    return app_main(sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
