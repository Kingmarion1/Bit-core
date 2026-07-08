#!/usr/bin/env python3

import sqlite3


class Database:

    def __init__(self, db_path):

        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row

        self.create_tables()

    # ------------------------------------------------------------

    def create_tables(self):

        cur = self.conn.cursor()

        cur.execute("""

        CREATE TABLE IF NOT EXISTS signatures(

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            txid TEXT,

            block_height INTEGER,

            block_time TEXT,

            input_index INTEGER,

            output_index INTEGER,

            address TEXT,

            pubkey TEXT,

            scriptpubkey TEXT,

            message_hash TEXT,

            r TEXT,

            s TEXT,

            sighash INTEGER,

            verified INTEGER DEFAULT 0

        )

        """)

        cur.execute("""

        CREATE INDEX IF NOT EXISTS idx_txid
        ON signatures(txid)

        """)

        cur.execute("""

        CREATE INDEX IF NOT EXISTS idx_pubkey
        ON signatures(pubkey)

        """)

        cur.execute("""

        CREATE INDEX IF NOT EXISTS idx_r
        ON signatures(r)

        """)

        self.conn.commit()

    # ------------------------------------------------------------

    def insert_signature(
        self,
        txid,
        block_height,
        block_time,
        input_index,
        output_index,
        address,
        pubkey,
        scriptpubkey,
        message_hash,
        r,
        s,
        sighash,
        verified=0
    ):

        cur = self.conn.cursor()

        cur.execute("""

        INSERT INTO signatures(

            txid,
            block_height,
            block_time,
            input_index,
            output_index,
            address,
            pubkey,
            scriptpubkey,
            message_hash,
            r,
            s,
            sighash,
            verified

        )

        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)

        """, (

            txid,
            block_height,
            block_time,
            input_index,
            output_index,
            address,
            pubkey,
            scriptpubkey,
            message_hash,
            r,
            s,
            sighash,
            verified

        ))

        self.conn.commit()

    # ------------------------------------------------------------

    def fetch_all(self):

        cur = self.conn.cursor()

        cur.execute("""

        SELECT *
        FROM signatures

        ORDER BY txid,input_index

        """)

        return cur.fetchall()

    # ------------------------------------------------------------

    def duplicate_r(self):

        cur = self.conn.cursor()

        cur.execute("""

        SELECT
            r,
            COUNT(*) AS total

        FROM signatures

        GROUP BY r

        HAVING COUNT(*) > 1

        ORDER BY total DESC

        """)

        return cur.fetchall()

    # ------------------------------------------------------------

    def signature_count(self):

        cur = self.conn.cursor()

        cur.execute("""

        SELECT COUNT(*)
        FROM signatures

        """)

        return cur.fetchone()[0]

    # ------------------------------------------------------------

    def update_verified(
        self,
        txid,
        input_index,
        verified
    ):

        cur = self.conn.cursor()

        cur.execute("""

        UPDATE signatures

        SET verified=?

        WHERE
            txid=?
        AND
            input_index=?

        """, (

            verified,
            txid,
            input_index

        ))

        self.conn.commit()

    # ------------------------------------------------------------

    def close(self):

        self.conn.close()
