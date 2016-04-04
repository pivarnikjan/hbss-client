# TODO CELE PREROBIT
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

class Verifier(KeyWrapper):
    def __init__(self, keypair):
        self.keypair = keypair
        if not self.keypair.public_key:
            raise ValueError(("Specified key has no public part, "
                              "and generation from private part (if available) "
                              "failed. Cannot be used to verify."))

    def verify_signature(self, message, utf8sig):
        '''Message and utf8sig should be strings. They will be byte-converted
        and passed to the verify_bin_signature method.'''
        return self.verify_bin_signature(bytes(message, 'utf-8'), self._parse_utf8_sig(utf8sig))

    def verify_bin_signature(self, message, binsig):
        '''This is the method responsible for actual verification of sigs.
        Message must be binary. Binsig must be a list of 512 64-byte values.
        Messages are first hash-digested, and the hash is converted to a
        list of boolean values representing the bits of the hash. Then,
        for each boolean of the signature, a hash from the pubkey is chosen
        and compared to the hash of the number in the binary signature.
        If the hashes of all numbers in the signature match the corresponding
        hashes in the pubkey, the sig is valid, and this returns True.
        Otherwise, this method returns False.'''
        bithash = self.bit_hash(self.hash_message(message))
        if self.keypair.debug:
            print("Bithash 1-30: ", ''.join([str(x) for x in bithash[:40]]))
            print("Counter", "Bit", "This Secret Num #", "Pubkey #", "Other Pubkey #", sep="\t")
        counter = 0
        for bit in bithash:
            public_hashes_for_bit = self.keypair.public_key[counter]
            this_number_hash = sha512(binsig[counter]).digest()
            # In python compound evaluations short-circuit, so if debug
            # is false, counter < 10 isn't even evaluated.
            if self.keypair.debug and counter < 10:
                # Get tib, the opposite of bit:
                if bit:
                    tib = 0
                else:
                    tib = 1
                print(counter, bit, base64.b64encode(this_number_hash[:10]),
                      base64.b64encode(public_hashes_for_bit[bit][:10]),
                      base64.b64encode(public_hashes_for_bit[tib][:10]), sep="\t")
            if this_number_hash != public_hashes_for_bit[bit]:
                # Hash mismatch, signature false.
                return False
            # Counter should run from 0 to 511
            counter += 1
        # No hash mismatch, signature valid.
        return True

    def _parse_utf8_sig(self, utf8sig):
        # NB: Should verify the general shape/format of the signature here.
        # Sig is a concatenation of 512 b64-encoded 64-byte numbers.
        # The length of such numbers is 88 when encoded.
        # Keypairs already have a string-digesting staticmethod, so use that.
        binary_sig = base64.b64decode(bytes(utf8sig, 'utf-8'))
        bin_sig_list = [x for x in self.keypair.string_digest(binary_sig, 64)]
        return bin_sig_list