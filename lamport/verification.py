"""
    Implementation of the Quantum-Computer-Resistant Lamport Signature scheme in Python 3
    Copyright (C) 2013  Cathal Garvey

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import json
from ssl import RAND_bytes as RNG

from utils.hbss_utills import bit_hash, hash_function_digest, importable_key
from lamport import keys_generation, signature


# TODO documentation


class Verifier:
    def __init__(self, signature_file, hash_fn_name):
        self.public_key = self._import_public_key(signature_file)
        if not signature_file:
            raise ValueError("Signature file is required !!!")
        self.hash_fn_name = hash_fn_name

    def verify_signature(self, message_sig, message):
        counter = 0
        bithash = bit_hash(hash_function_digest(message, self.hash_fn_name))

        for bit in bithash:
            public_hashes_for_bit = self.public_key[counter]
            this_number_hash = hash_function_digest(message_sig[counter], self.hash_fn_name)

            if this_number_hash != public_hashes_for_bit[bit]:
                # Hash mismatch, signature false.
                return False
            counter += 1
        # No hash mismatch, signature valid.
        return True

    @staticmethod
    def _import_public_key(signature_file):
        with open(signature_file, 'r') as json_file:
            sig = json.load(json_file)

        vrfy = sig['vrfy']
        list_vrfy = importable_key(vrfy)

        return list_vrfy


def test():
    key_pair = keys_generation.Keypair(RNG=RNG, hash_fn=["sha256", 256])
    sig = signature.Signer(key_pair, "sha256")
    exp_sig = sig.generate_signature('jano'.encode('utf-8'))
    sig.export_signature(exp_sig, 'sig.json')

    vrfy_sig = sig.import_signature(sig.load_signature('sig.json'))
    vrfy = Verifier("sig.json", "sha256").verify_signature(vrfy_sig, "marek".encode('utf-8'))
    print(vrfy)


if __name__ == '__main__':
    test()
