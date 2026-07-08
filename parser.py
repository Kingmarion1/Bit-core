#!/usr/bin/env python3

import os
import requests

from bitcoin.core import x
from bitcoin.core import CTransaction
from bitcoin.core.script import (
    CScript,
    SignatureHash,
    SIGHASH_ALL
)

BASE_URL = "https://blockstream.info/api"


class Parser:

    def __init__(self, db):

        self.db = db

    # -------------------------------------------------------------

    def load_transaction(self, filename):

        with open(filename, "r") as f:

            raw = f.read().strip()

        return CTransaction.deserialize(x(raw))

    # -------------------------------------------------------------

    def decode_signature(self, script):

        script = bytes(script)

        if len(script) == 0:
            return None

        sig_len = script[0]

        signature = script[1:1 + sig_len]

        sighash = signature[-1]

        der = signature[:-1]

        pub_len = script[1 + sig_len]

        pubkey = script[
            2 + sig_len:
            2 + sig_len + pub_len
        ]

        if der[0] != 0x30:
            return None

        r_len = der[3]

        r = der[4:4 + r_len]

        s_start = 4 + r_len + 2

        s_len = der[4 + r_len + 1]

        s = der[s_start:s_start + s_len]

        if len(r) == 33 and r[0] == 0:
            r = r[1:]

        if len(s) == 33 and s[0] == 0:
            s = s[1:]

        return {

            "pubkey": pubkey.hex(),

            "r": r.hex(),

            "s": s.hex(),

            "sighash": sighash

        }

    # -------------------------------------------------------------

    def txid_from_filename(self, filename):

        return os.path.basename(filename).replace(".hex", "")

    # -------------------------------------------------------------
    # Download previous transaction
    # -------------------------------------------------------------

    def fetch_prev_tx(self, txid):

        url = f"{BASE_URL}/tx/{txid}/hex"

        r = requests.get(url, timeout=30)

        if r.status_code != 200:
            raise Exception(f"Unable to fetch previous TX: {txid}")

        raw = r.text.strip()

        return CTransaction.deserialize(x(raw))

    # -------------------------------------------------------------
    # Fetch ScriptPubKey of spent output
    # -------------------------------------------------------------

    def get_scriptpubkey(self, vin):

        prev_txid = bytes(vin.prevout.hash)[::-1].hex()

        prev_index = vin.prevout.n

        prev_tx = self.fetch_prev_tx(prev_txid)

        prev_output = prev_tx.vout[prev_index]

        return CScript(prev_output.scriptPubKey)

    # -------------------------------------------------------------
    # Compute Exact Bitcoin Message Hash (H)
    # -------------------------------------------------------------

    def compute_h(self, tx, input_index, script_pubkey):

        sighash = SignatureHash(

            script_pubkey,

            tx,

            input_index,

            SIGHASH_ALL

        )

        return sighash.hex()

    # -------------------------------------------------------------
    # Build record for one input
    # -------------------------------------------------------------

    def build_record(self, tx, input_index):

        vin = tx.vin[input_index]

        decoded = self.decode_signature(vin.scriptSig)

        if decoded is None:
            return None

        script_pubkey = self.get_scriptpubkey(vin)

        H = self.compute_h(

            tx,

            input_index,

            script_pubkey

        )

        return {

            "pubkey": decoded["pubkey"],

            "r": decoded["r"],

            "s": decoded["s"],

            "sighash": decoded["sighash"],

            "scriptpubkey": script_pubkey.hex(),

            "message_hash": H

        }

    # -------------------------------------------------------------
    # Scan one transaction
    # -------------------------------------------------------------

    def scan_transaction(self, filename):

        txid = self.txid_from_filename(filename)

        print(f"[SCAN] {txid}")

        tx = self.load_transaction(filename)

        for index in range(len(tx.vin)):

            try:

                record = self.build_record(tx, index)

                if record is None:
                    continue

                self.db.insert_signature(

                    txid=txid,

                    block_height=None,

                    block_time=None,

                    input_index=index,

                    output_index=None,

                    address=None,

                    pubkey=record["pubkey"],

                    scriptpubkey=record["scriptpubkey"],

                    message_hash=record["message_hash"],

                    r=record["r"],

                    s=record["s"],

                    sighash=record["sighash"],

                    verified=0

                )

                print(
                    f"    Input {index} -> OK"
                )

            except Exception as e:

                print(
                    f"    Input {index} -> FAILED"
                )

                print(
                    f"    {e}"
                )

    # -------------------------------------------------------------
    # Scan directory
    # -------------------------------------------------------------

    def scan_directory(self, folder):

        files = sorted(

            f for f in os.listdir(folder)

            if f.endswith(".hex")

        )

        print("\n========================================")
        print("Scanning Transactions")
        print("========================================")

        for file in files:

            path = os.path.join(folder, file)

            self.scan_transaction(path)

        print("\nScan Complete.")

        print(
            f"Database contains {self.db.signature_count()} signatures."
        )
