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
from hbss_utills import bit_hash,hash_function_digest

class Signer():
    def __init__(self, keypair):
        self.keypair = keypair
        if not self.keypair.private_key:
            raise ValueError("Specified key has no private part; cannot sign!")

    def generate_signature(self, message):
        '''Generate base-64 encoded string signature in utf-8.
        Signature is a concatenation of _generate_signature output.
        Verifiers can regenerate the binary signature by byte-decoding
        from utf-8, b64-decoding the binary, and breaking into 64byte chunks.
        '''
        binary_sig = self._generate_signature(message)
        concat_bin_sig = b''.join(binary_sig)
        b64_bin_sig = base64.b64encode(concat_bin_sig)
        utf8_sig = str(b64_bin_sig, 'utf-8')
        return utf8_sig

    def _generate_signature(self, message):
        'Generate binary signature as a list of 64-byte binary private numbers.'
        bithash = bit_hash(hash_function_digest(message,hash_fn_name="sha512"))
        Revealed_Numbers = []
        counter = 0
        for bit in bithash:
            private_numbers_for_bit = self.keypair.private_key[counter]
            # Below: if bit is true, int(bit) is 1, if False, 0.
            Revealed_Numbers.append(private_numbers_for_bit[bit])
            counter += 1
        return Revealed_Numbers