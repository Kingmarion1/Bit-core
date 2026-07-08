#!/usr/bin/env python3

import os
import csv
import json


class Exporter:

    def __init__(self, db):

        self.db = db

        self.export_dir = "exports"

        os.makedirs(

            self.export_dir,

            exist_ok=True

        )

    # ---------------------------------------------------------
    # Get all database rows
    # ---------------------------------------------------------

    def records(self):

        return self.db.fetch_all()

    # ---------------------------------------------------------
    # Export CSV
    # ---------------------------------------------------------

    def export_csv(self):

        rows = self.records()

        filename = os.path.join(

            self.export_dir,

            "signatures.csv"

        )

        with open(

            filename,

            "w",

            newline="",

            encoding="utf-8"

        ) as f:

            writer = csv.writer(f)

            writer.writerow([

                "txid",

                "input_index",

                "output_index",

                "pubkey",

                "scriptpubkey",

                "message_hash",

                "r",

                "s",

                "sighash",

                "verified"

            ])

            for row in rows:

                writer.writerow([

                    row["txid"],

                    row["input_index"],

                    row["output_index"],

                    row["pubkey"],

                    row["scriptpubkey"],

                    row["message_hash"],

                    row["r"],

                    row["s"],

                    row["sighash"],

                    row["verified"]

                ])

        print(f"[✓] CSV exported -> {filename}")

    # ---------------------------------------------------------
    # Export JSON
    # ---------------------------------------------------------

    def export_json(self):

        rows = self.records()

        filename = os.path.join(

            self.export_dir,

            "signatures.json"

        )

        data = []

        for row in rows:

            data.append(dict(row))

        with open(

            filename,

            "w",

            encoding="utf-8"

        ) as f:

            json.dump(

                data,

                f,

                indent=4

            )

        print(f"[✓] JSON exported -> {filename}")

      # ---------------------------------------------------------
    # Export Duplicate r Values
    # ---------------------------------------------------------

    def export_duplicate_r(self):

        rows = self.records()

        groups = {}

        for row in rows:

            groups.setdefault(

                row["r"],

                []

            ).append(dict(row))

        duplicates = {

            r: records

            for r, records in groups.items()

            if len(records) > 1

        }

        filename = os.path.join(

            self.export_dir,

            "duplicate_r.json"

        )

        with open(

            filename,

            "w",

            encoding="utf-8"

        ) as f:

            json.dump(

                duplicates,

                f,

                indent=4

            )

        print(f"[✓] Duplicate-r exported -> {filename}")

    # ---------------------------------------------------------
    # Export Public Keys
    # ---------------------------------------------------------

    def export_pubkeys(self):

        filename = os.path.join(

            self.export_dir,

            "pubkeys.txt"

        )

        pubkeys = sorted({

            row["pubkey"]

            for row in self.records()

        })

        with open(

            filename,

            "w",

            encoding="utf-8"

        ) as f:

            for pubkey in pubkeys:

                f.write(pubkey + "\n")

        print(f"[✓] Public Keys exported -> {filename}")

    # ---------------------------------------------------------
    # Export Message Hashes
    # ---------------------------------------------------------

    def export_hashes(self):

        filename = os.path.join(

            self.export_dir,

            "message_hashes.txt"

        )

        with open(

            filename,

            "w",

            encoding="utf-8"

        ) as f:

            for row in self.records():

                f.write(row["message_hash"] + "\n")

        print(f"[✓] Message Hashes exported -> {filename}")

    # ---------------------------------------------------------
    # Export Summary
    # ---------------------------------------------------------

    def export_summary(self):

        rows = self.records()

        total = len(rows)

        verified = sum(

            row["verified"]

            for row in rows

        )

        unique_pubkeys = len({

            row["pubkey"]

            for row in rows

        })

        unique_hashes = len({

            row["message_hash"]

            for row in rows

        })

        duplicate_r = {}

        for row in rows:

            duplicate_r.setdefault(

                row["r"],

                0

            )

            duplicate_r[row["r"]] += 1

        duplicate_sets = sum(

            1

            for count in duplicate_r.values()

            if count > 1

        )

        filename = os.path.join(

            self.export_dir,

            "summary.txt"

        )

        with open(

            filename,

            "w",

            encoding="utf-8"

        ) as f:

            f.write("========== FORENSIC SUMMARY ==========\n\n")

            f.write(f"Total Signatures : {total}\n")
            f.write(f"Verified         : {verified}\n")
            f.write(f"Failed           : {total - verified}\n")
            f.write(f"Unique PubKeys   : {unique_pubkeys}\n")
            f.write(f"Unique Hashes(H) : {unique_hashes}\n")
            f.write(f"Duplicate r Sets : {duplicate_sets}\n")

        print(f"[✓] Summary exported -> {filename}")

    # ---------------------------------------------------------
    # Export Everything
    # ---------------------------------------------------------

    def run(self):

        print("\n" + "=" * 70)
        print("Exporting Forensic Dataset")
        print("=" * 70)

        self.export_csv()

        self.export_json()

        self.export_duplicate_r()

        self.export_pubkeys()

        self.export_hashes()

        self.export_summary()

        print("=" * 70)

        print("Export Complete.")

        print("=" * 70)
