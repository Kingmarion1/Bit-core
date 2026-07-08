#!/usr/bin/env python3

import os
import time
import requests

BASE_URL = "https://blockstream.info/api"


class Downloader:

    def __init__(self, db=None):

        self.db = db

        os.makedirs("rawtx", exist_ok=True)

    # ---------------------------------------------------------

    def tx_path(self, txid):

        return os.path.join(
            "rawtx",
            f"{txid}.hex"
        )

    # ---------------------------------------------------------

    def exists(self, txid):

        return os.path.isfile(
            self.tx_path(txid)
        )

    # ---------------------------------------------------------

    def fetch_hex(self, txid):

        url = f"{BASE_URL}/tx/{txid}/hex"

        r = requests.get(
            url,
            timeout=30
        )

        if r.status_code != 200:

            raise Exception(
                f"{txid} -> HTTP {r.status_code}"
            )

        return r.text.strip()

    # ---------------------------------------------------------

    def save_hex(self, txid, raw_hex):

        with open(
            self.tx_path(txid),
            "w"
        ) as f:

            f.write(raw_hex)

    # ---------------------------------------------------------

    def download_one(self, txid):

        if self.exists(txid):

            print(
                f"[SKIP] {txid}"
            )

            return

        try:

            raw_hex = self.fetch_hex(txid)

            self.save_hex(
                txid,
                raw_hex
            )

            print(
                f"[OK]   {txid}"
            )

        except Exception as e:

            print(
                f"[FAIL] {txid}"
            )

            print(e)

    # ---------------------------------------------------------

    def download(self, txids):

        total = len(txids)

        print("\nDownloading raw transactions...")
        print("-" * 60)

        for idx, txid in enumerate(txids, start=1):

            print(
                f"[{idx}/{total}]",
                end=" "
            )

            self.download_one(txid)

            time.sleep(0.15)

        print("-" * 60)
        print(
            f"Completed: {total} transaction(s)"
      )
