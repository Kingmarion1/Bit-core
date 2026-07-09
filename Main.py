#!/usr/bin/env python3
# ============================================================
# Bit-Core v1.0
# Bitcoin ECDSA Forensic Analyzer
# Build by @prominent_mairo | t.me/jahbless_02
# ============================================================

import os
import sys
import argparse
import logging
from pathlib import Path

from database import Database
from collector import Collector
from downloader import Downloader
from parser import Parser
from verifier import Verifier
from analysis import Analyzer
from exporter import Exporter


# ============================================================
# Banner
# ============================================================

BANNER = r"""
============================================================
                     Bit-Core v1.0
            Bitcoin ECDSA Forensic Analyzer
      Build by @prominent_mairo | t.me/jahbless_02
============================================================
"""


# ============================================================
# Logging
# ============================================================

LOG = logging.getLogger("bit-core")


def configure_logging(verbose: int) -> None:
    """
    Configure logging level.

    -v   -> INFO
    -vv  -> DEBUG
    """

    level = logging.WARNING

    if verbose == 1:
        level = logging.INFO

    elif verbose >= 2:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
    )


# ============================================================
# Directories
# ============================================================

PROJECT_DIRS = [
    "rawtx",
    "database",
    "reports",
    "exports",
]


def ensure_directories() -> None:

    for folder in PROJECT_DIRS:
        Path(folder).mkdir(
            parents=True,
            exist_ok=True,
        )


# ============================================================
# Database
# ============================================================

DATABASE_PATH = "database/forensic.db"


def get_database(path: str = DATABASE_PATH) -> Database:
    """
    Returns database connection.
    """

    return Database(path)


# ============================================================
# Pipeline Steps
# ============================================================

def run_collect(target: str):

    LOG.info("Collecting transactions...")

    collector = Collector(target)

    txids = collector.collect()

    LOG.info(
        "Collected %d transaction(s).",
        len(txids),
    )

    return txids


def run_download(db: Database, txids):

    LOG.info("Downloading raw transactions...")

    downloader = Downloader(db)

    downloader.download(txids)

    LOG.info("Download complete.")


def run_parse(db: Database):

    LOG.info("Parsing raw transactions...")

    parser = Parser(db)

    parser.scan_directory("rawtx")

    LOG.info("Parser complete.")


def run_verify(db: Database):

    LOG.info("Verifying ECDSA signatures...")

    verifier = Verifier(db)

    verifier.run()

    LOG.info("Verification complete.")


def run_analysis(db: Database):

    LOG.info("Running forensic analysis...")

    analyzer = Analyzer(db)

    analyzer.run()

    LOG.info("Analysis complete.")


def run_export(db: Database):

    LOG.info("Exporting reports...")

    exporter = Exporter(db)

    exporter.run()

    LOG.info("Export complete.")

# ============================================================
# Full Pipeline
# ============================================================

def pipeline(target: str):

    db = get_database()

    try:

        txids = run_collect(target)

        if not txids:
            LOG.warning("No transactions were found.")
            return

        run_download(db, txids)

        run_parse(db)

        run_verify(db)

        run_analysis(db)

        run_export(db)

        print("\n============================================================")
        print(" Pipeline Completed Successfully")
        print("============================================================\n")

    finally:
        db.close()


# ============================================================
# Command Line Interface
# ============================================================

def build_parser():

    parser = argparse.ArgumentParser(
        prog="bit-core",
        description="Bitcoin ECDSA Forensic Analyzer",
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Bitcoin Address or Compressed Public Key",
    )

    parser.add_argument(
        "--collect",
        action="store_true",
        help="Collect transaction IDs",
    )

    parser.add_argument(
        "--download",
        action="store_true",
        help="Download raw transactions",
    )

    parser.add_argument(
        "--parse",
        action="store_true",
        help="Parse downloaded raw transactions",
    )

    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify every ECDSA signature",
    )

    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Run forensic analysis",
    )

    parser.add_argument(
        "--export",
        action="store_true",
        help="Export reports",
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Run complete forensic pipeline",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity",
    )

    return parser


# ============================================================
# Main
# ============================================================

def main():

    print(BANNER)

    ensure_directories()

    parser = build_parser()

    args = parser.parse_args()

    configure_logging(args.verbose)

    if not any([
        args.collect,
        args.download,
        args.parse,
        args.verify,
        args.analyze,
        args.export,
        args.all,
    ]):

        parser.print_help()
        sys.exit(0)

    if not args.target and (
        args.collect or
        args.all
    ):
        parser.error(
            "Target Address/Public Key is required."
        )

    db = get_database()

    try:

        # ----------------------------------------------------

        if args.collect:

            run_collect(args.target)

        # ----------------------------------------------------

        if args.download:

            txids = run_collect(args.target)

            run_download(db, txids)

        # ----------------------------------------------------

        if args.parse:

            run_parse(db)

        # ----------------------------------------------------

        if args.verify:

            run_verify(db)

        # ----------------------------------------------------

        if args.analyze:

            run_analysis(db)

        # ----------------------------------------------------

        if args.export:

            run_export(db)

        # ----------------------------------------------------

        if args.all:

            db.close()

            pipeline(args.target)

            return

    finally:

        db.close()


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print("\n\nInterrupted by user.")

        sys.exit(0)

    except Exception as e:

        LOG.exception(e)

        print("\nFatal Error:")
        print(e)

        sys.exit(1)
