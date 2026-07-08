#!/usr/bin/env python3

import json
import hashlib

from ecdsa import (
    SECP256k1,
    VerifyingKey,
    ellipticcurve,
    util
)

curve = SECP256k1.curve
generator = SECP256k1.generator
order = generator.order()


class Verifier:

    def __init__(self, db):

        self.db = db

    # ---------------------------------------------------------
    # Modular Square Root (p % 4 == 3)
    # ---------------------------------------------------------

    def mod_sqrt(self, a, p):

        return pow(a, (p + 1) // 4, p)

    # ---------------------------------------------------------
    # SEC Compressed Public Key -> EC Point
    # ---------------------------------------------------------

    def decompress_pubkey(self, pubkey_hex):

        pub = bytes.fromhex(pubkey_hex)

        prefix = pub[0]

        if prefix == 4:

            return VerifyingKey.from_string(
                pub[1:],
                curve=SECP256k1
            )

        if prefix not in (2, 3):

            raise ValueError("Invalid SEC Public Key")

        x = int.from_bytes(pub[1:], "big")

        p = curve.p()

        alpha = (pow(x, 3, p) + 7) % p

        beta = self.mod_sqrt(alpha, p)

        if (beta & 1) != (prefix & 1):

            beta = p - beta

        point = ellipticcurve.Point(

            curve,

            x,

            beta,

            order

        )

        return VerifyingKey.from_public_point(

            point,

            curve=SECP256k1

        )

    # ---------------------------------------------------------
    # r,s -> DER Signature
    # ---------------------------------------------------------

    def signature_bytes(

        self,

        r_hex,

        s_hex

    ):

        r = int(r_hex, 16)

        s = int(s_hex, 16)

        return util.sigencode_der(

            r,

            s,

            order

        )

    # ---------------------------------------------------------
    # Low-S Normalization
    # ---------------------------------------------------------

    def normalize_s(self, s):

        if s > order // 2:

            return order - s

        return s

    # ---------------------------------------------------------
    # SHA256 Helper
    # ---------------------------------------------------------

    def sha256(self, data):

        return hashlib.sha256(data).digest()
      
    # ---------------------------------------------------------
    # Verify one signature
    # ---------------------------------------------------------

    def verify_signature(

        self,

        pubkey_hex,

        r_hex,

        s_hex,

        message_hash_hex

    ):

        try:

            vk = self.decompress_pubkey(pubkey_hex)

            r = int(r_hex, 16)

            s = int(s_hex, 16)

            s = self.normalize_s(s)

            signature = util.sigencode_string(

                r,

                s,

                order

            )

            verified = vk.verify_digest(

                signature,

                bytes.fromhex(message_hash_hex),

                sigdecode=util.sigdecode_string

            )

            return verified

        except Exception as e:

            return False

    # ---------------------------------------------------------
    # Verify database record
    # ---------------------------------------------------------

    def verify_record(

        self,

        row

    ):

        ok = self.verify_signature(

            row["pubkey"],

            row["r"],

            row["s"],

            row["message_hash"]

        )

        self.db.update_verified(

            row["txid"],

            row["input_index"],

            int(ok)

        )

        return ok

    # ---------------------------------------------------------
    # Verify all signatures for one public key
    # ---------------------------------------------------------

    def verify_pubkey(

        self,

        pubkey

    ):

        rows = [

            r for r in self.db.fetch_all()

            if r["pubkey"] == pubkey

        ]

        passed = 0

        failed = 0

        for row in rows:

            if self.verify_record(row):

                passed += 1

            else:

                failed += 1

        return {

            "pubkey": pubkey,

            "total": len(rows),

            "passed": passed,

            "failed": failed

        }

    # ---------------------------------------------------------
    # Detect reused nonce (duplicate r)
    # ---------------------------------------------------------

    def duplicate_r_groups(self):

        rows = self.db.fetch_all()

        groups = {}

        for row in rows:

            groups.setdefault(

                row["r"],

                []

            ).append(row)

        return {

            r: items

            for r, items in groups.items()

            if len(items) > 1

      }

    # ---------------------------------------------------------
    # Verify Entire Database
    # ---------------------------------------------------------

    def run(self):

        rows = self.db.fetch_all()

        total = len(rows)

        passed = 0
        failed = 0

        print("\n" + "=" * 80)
        print("Bitcoin Signature Verification")
        print("=" * 80)

        for i, row in enumerate(rows, start=1):

            ok = self.verify_record(row)

            status = "PASS" if ok else "FAIL"

            print(

                f"[{i}/{total}] "
                f"{status}  "
                f"Input={row['input_index']}  "
                f"TXID={row['txid']}"

            )

            if ok:
                passed += 1
            else:
                failed += 1

        print("\n" + "=" * 80)
        print("Verification Finished")
        print("=" * 80)

        print(f"Total Signatures : {total}")
        print(f"Verified         : {passed}")
        print(f"Failed           : {failed}")

        duplicates = self.duplicate_r_groups()

        print(f"Duplicate r Sets : {len(duplicates)}")

        if duplicates:

            print("\nDuplicate r values")

            for r, records in duplicates.items():

                print("-" * 80)

                print("r =", r)

                for rec in records:

                    print(
                        f"  {rec['txid']}  "
                        f"Input {rec['input_index']}"
                    )

        report = {

            "total": total,

            "verified": passed,

            "failed": failed,

            "duplicate_r_sets": len(duplicates),

            "duplicate_r": {}

        }

        for r, records in duplicates.items():

            report["duplicate_r"][r] = [

                {

                    "txid": rec["txid"],

                    "input": rec["input_index"],

                    "pubkey": rec["pubkey"],

                    "message_hash": rec["message_hash"]

                }

                for rec in records

            ]

        with open(

            "verification_report.json",

            "w"

        ) as f:

            json.dump(

                report,

                f,

                indent=4

            )

        print("\nJSON report written to")

        print("verification_report.json")

        print("=" * 80)
