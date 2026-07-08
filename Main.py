#!/usr/bin/env python3

import os
from collector import Collector
from downloader import Downloader
from parser import Parser
from database import Database
from analysis import Analyzer


BANNER = r"""
============================================================
                     Bit-Core v1.0
            Bitcoin ECDSA Forensic Analyzer
            Build by @prominent_mairo t.me/jahbless_02
============================================================
"""


def ensure_dirs():

    folders = [
        "rawtx",
        "database",
        "reports"
    ]

    for folder in folders:
        os.makedirs(folder, exist_ok=True)


def main():

    print(BANNER)

    ensure_dirs()

    target = input("Target Address/PublicKey > ").strip()

    db = Database("database/forensic.db")

    collector = Collector(target)
    downloader = Downloader(db)
    parser = Parser(db)
    analyzer = Analyzer(db)

    txids = collector.collect()

    downloader.download(txids)

    parser.scan_directory("rawtx")

    analyzer.run()

    print("\nCompleted.\n")


if __name__ == "__main__":
    main()
