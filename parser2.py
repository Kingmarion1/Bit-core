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
