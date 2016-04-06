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
import base64
import json
from ssl import RAND_bytes as RNG

from lamport import keys_generation
from utils.hbss_utills import bit_hash, hash_function_digest


class Signer():
    def __init__(self, keypair):
        self.keypair = keypair
        if not self.keypair.private_key:
            raise ValueError("Specified key has no private part; cannot sign!")

    def generate_signature(self, message):
        bithash = bit_hash(hash_function_digest(message, hash_fn_name="sha512"))
        Revealed_Numbers = []
        counter = 0
        for bit in bithash:
            private_numbers_for_bit = self.keypair.private_key[counter]
            Revealed_Numbers.append(private_numbers_for_bit[bit])
            counter += 1
        return Revealed_Numbers

    def _format_signature(self, signature):
        exportable_signature = []
        for unit in signature:
            exportable_signature.append(str(base64.b64encode(bytes(unit)), encoding='utf-8'))
        return exportable_signature

    def export_signature(self, message, file):
        export_list = []
        export_list.append({'sig': self._format_signature(self.generate_signature(message))})

        with open(file, 'w') as jsonFile:
            json.dump(export_list, jsonFile, indent=2)


def test():
    key_pair = keys_generation.Keypair(RNG=RNG, hash_function="sha256", hash_fn_length=256)
    Signer(key_pair).export_signature('jano'.encode('utf-8'), 'signature.json')


if __name__ == '__main__':
    test()
