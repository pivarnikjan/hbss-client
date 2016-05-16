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
import base64
import json
from ssl import RAND_bytes as RNG

from lamport import keys_generation
from utils.hbss_utills import bit_hash, hash_function_digest, exportable_key, exportable_key_single


# TODO documentation


class Signer:
    def __init__(self, key_pair, hash_fn_name):
        self.key_pair = key_pair
        if not self.key_pair.private_key:
            raise ValueError("Specified key has no private part. Cannot sign!")
        self.hash_fn_name = hash_fn_name

    def generate_signature(self, message):
        """

        Args:
            message:

        Returns:

        """
        bithash = bit_hash(hash_function_digest(message, self.hash_fn_name))
        revealed_numbers = []
        counter = 0
        for bit in bithash:
            private_numbers_for_bit = self.key_pair.private_key[counter]
            revealed_numbers.append(private_numbers_for_bit[bit])
            counter += 1
        return revealed_numbers

    def export_signature(self, signature, file_name):
        """

        Args:
            signature:
            file_name:

        Returns:

        """
        export_dict = {'sig': exportable_key_single(signature), 'vrfy': exportable_key(self.key_pair.public_key)}

        with open(file_name, 'w') as f:
            f.write(json.dumps(export_dict, f, indent=2))

    @staticmethod
    def import_signature(signature):
        """

        Args:
            signature:

        Returns:

        """
        import_list = []
        for unit in signature['sig']:
            import_list.append(base64.b64decode(bytes(unit, 'utf-8')))
        return import_list

    @staticmethod
    def load_signature(file):
        """

        Args:
            file:

        Returns:

        """
        with open(file, 'r') as data:
            signature = json.load(data)

        return signature


def test():
    key_pair = keys_generation.Keypair(RNG=RNG, hash_fn=["sha256", 256])
    # key_pair = keys_generation.Keypair(RNG=RNG)

    sign = Signer(key_pair, "sha256")
    signature = sign.generate_signature("jano".encode('utf-8'))
    sign.export_signature(signature, "signature.json")

    tmp = sign.load_signature("signature.json")
    formatS = sign.import_signature(tmp)
    print(formatS)

if __name__ == '__main__':
    test()
