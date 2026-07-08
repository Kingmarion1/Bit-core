#!/usr/bin/env python3

import requests

BASE = "https://blockstream.info/api"


def get_address_txs(address):
    url = f"{BASE}/address/{address}/txs"

    r = requests.get(url, timeout=30)

    if r.status_code != 200:
        print("Request failed:", r.status_code)
        return

    txs = r.json()

    print(f"\nTransactions Found: {len(txs)}\n")

    for tx in txs:
        print(tx["txid"])


if __name__ == "__main__":

    address = input("Bitcoin Address: ").strip()

    get_address_txs(address)
