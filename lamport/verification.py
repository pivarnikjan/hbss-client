# TODO doplnit komentare jednotlivych tried a metod
"""
    Implementation of the Quantum-Computer-Resistant Lamport Signature scheme in Python 3
    Copyright (C) 2013  Cathal Garvey

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
from ssl import RAND_bytes as RNG

from utils.hbss_utills import bit_hash, hash_function_digest
from lamport import keys_generation, signature


class Verifier():
    def __init__(self, keypair, hash_fn_name):
        self.keypair = keypair
        if not self.keypair.public_key:
            raise ValueError(("Specified key has no public part, "
                              "and generation from private part (if available) "
                              "failed. Cannot be used to verify."))
        self.hash_fn_name = hash_fn_name

    def verify_signature(self, signature, message):
        counter = 0
        bithash = bit_hash(hash_function_digest(message, self.hash_fn_name))

        for bit in bithash:
            public_hashes_for_bit = self.keypair.public_key[counter]
            this_number_hash = hash_function_digest(signature[counter], self.hash_fn_name)

            if this_number_hash != public_hashes_for_bit[bit]:
                # Hash mismatch, signature false.
                return False
            counter += 1
        # No hash mismatch, signature valid.
        return True

def test():
    key_pair = keys_generation.Keypair(RNG=RNG, hash_function="sha256", hash_fn_length=256)
    sig = signature.Signer(key_pair, "sha256")
    exp_sig = sig.generate_signature('jano'.encode('utf-8'))
    sig.export_signature(exp_sig, 'sig.json')
    vrfy_sig = sig.import_signature(sig.load_signature('sig.json'))
    vrfy = Verifier(key_pair, "sha256").verify_signature(vrfy_sig, "jano".encode('utf-8'))
    print(vrfy)


if __name__ == '__main__':
    test()
