#!/usr/bin/env python3

from collections import Counter


class Analyzer:

    def __init__(self, db):

        self.db = db

    # ---------------------------------------------------------

    def duplicate_r(self):

        rows = self.db.duplicate_r()

        print("\n" + "=" * 70)
        print("Duplicate r Analysis")
        print("=" * 70)

        if not rows:

            print("No duplicate r values found.")

            return

        for row in rows:

            print(f"\nr : {row['r']}")
            print(f"Occurrences : {row['total']}")

    # ---------------------------------------------------------

    def pubkey_statistics(self):

        rows = self.db.fetch_all()

        counter = Counter()

        for row in rows:

            counter[row["pubkey"]] += 1

        print("\n" + "=" * 70)
        print("Public Key Statistics")
        print("=" * 70)

        if not counter:

            print("No public keys found.")
            return

        for pubkey, total in counter.most_common():

            print(f"{pubkey}")
            print(f"Signatures : {total}\n")

    # ---------------------------------------------------------

    def signature_statistics(self):

        rows = self.db.fetch_all()

        total = len(rows)

        verified = sum(
            1 for row in rows
            if row["verified"] == 1
        )

        print("\n" + "=" * 70)
        print("Signature Statistics")
        print("=" * 70)

        print(f"Total Signatures : {total}")
        print(f"Verified         : {verified}")
        print(f"Unverified       : {total - verified}")

    # ---------------------------------------------------------

    def message_hash_statistics(self):

        rows = self.db.fetch_all()

        hashes = set()

        for row in rows:

            hashes.add(row["message_hash"])

        print("\n" + "=" * 70)
        print("Message Hash Statistics")
        print("=" * 70)

        print(f"Unique H values : {len(hashes)}")

    # ---------------------------------------------------------

    def summary(self):

        rows = self.db.fetch_all()

        print("\n" + "=" * 70)
        print("Database Summary")
        print("=" * 70)

        print(f"Records : {len(rows)}")

    # ---------------------------------------------------------

    def run(self):

        self.summary()

        self.signature_statistics()

        self.message_hash_statistics()

        self.pubkey_statistics()

        self.duplicate_r()

        print("\nAnalysis Complete.\n")
