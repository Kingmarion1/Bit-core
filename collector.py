#!/usr/bin/env python3

import hashlib
import requests

BASE_URL = "https://blockstream.info/api"


class Collector:

    def __init__(self, target):

        self.target = target.strip()

        if self.target.startswith(("02", "03", "04")):
            self.address = self.pubkey_to_address(self.target)
        else:
            self.address = self.target

        print(f"\nTarget Address : {self.address}")

    # ---------------------------------------------------------

    def hash160(self, data):

        sha = hashlib.sha256(data).digest()

        ripemd = hashlib.new("ripemd160")
        ripemd.update(sha)

        return ripemd.digest()

    # ---------------------------------------------------------

    def b58encode(self, data):

        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        n = int.from_bytes(data, "big")

        out = ""

        while n > 0:
            n, r = divmod(n, 58)
            out = alphabet[r] + out

        pad = 0

        for b in data:
            if b == 0:
                pad += 1
            else:
                break

        return "1" * pad + out

    # ---------------------------------------------------------

    def pubkey_to_address(self, pubkey_hex):

        pubkey = bytes.fromhex(pubkey_hex)

        h160 = self.hash160(pubkey)

        payload = b"\x00" + h160

        checksum = hashlib.sha256(
            hashlib.sha256(payload).digest()
        ).digest()[:4]

        return self.b58encode(payload + checksum)

    # ---------------------------------------------------------

    def collect(self):

        print("\nCollecting transactions...")

        txids = []

        url = f"{BASE_URL}/address/{self.address}/txs"

        while True:

            r = requests.get(url, timeout=30)

            if r.status_code != 200:
                raise Exception(
                    f"HTTP {r.status_code}"
                )

            page = r.json()

            if not page:
                break

            for tx in page:

                txid = tx["txid"]

                if txid not in txids:
                    txids.append(txid)

            if len(page) < 25:
                break

            last = page[-1]["txid"]

            url = (
                f"{BASE_URL}/address/"
                f"{self.address}/txs/chain/{last}"
            )

        print(f"Transactions Found : {len(txids)}")

        return txids
