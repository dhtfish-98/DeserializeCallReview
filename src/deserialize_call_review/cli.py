"""JSON-only local-source review. Source and input paths are never printed."""

import argparse
import json

from . import __version__
from .analyzer import Report, review_file


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid_cli_arguments")


def main(argv=None):
    parser = _Parser(description="Offline Python AST call review; exploitability remains OPEN.")
    parser.add_argument("source", help="one regular UTF-8 Python source file; no symlinks")
    parser.add_argument("--version", action="version", version=__version__)
    try:
        args = parser.parse_args(argv)
        report = review_file(args.source)
    except ValueError:
        report = Report("OPEN", "invalid_cli_arguments")
    print(json.dumps(report.to_dict(), sort_keys=True, ensure_ascii=True))
    return {"NO_REVIEW_FINDINGS": 0, "REVIEW": 1, "OPEN": 2}[report.status]
