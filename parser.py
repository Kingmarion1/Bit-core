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
