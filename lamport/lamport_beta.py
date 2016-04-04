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

import os
import bitstring
import base64
import json
from hashlib import sha512

try:
    from ssl import RAND_bytes as RNG
except ImportError:
    from Crypto import Random as RNG


class Keypair:

    @staticmethod
    def _bin_b64str(binary_stuff):
        'Shorthand: Converts bytes into b64-encoded strings.'
        return str(base64.b64encode(binary_stuff), 'utf-8')

    @staticmethod
    def _b64str_bin(b64_encoded_stuff):
        'Shorthand: Restores bytes data from b64-encoded strings.'
        return base64.b64decode(bytes(b64_encoded_stuff, 'utf-8'))

    def __init__(self, private_seed=None, key_data=None, RNG=None, hash_function=None, hash_fn_length=None,
                 all_RNG=False):

        if private_seed:
            private_seed = self.import_seed(private_seed)
            self.private_key, self.public_key, self.rng_secret = self.generate_hash_chain_key_pair(private_seed)
        elif key_data:
            self.private_key, self.public_key = self.import_key_pair(key_data)
            self.rng_secret = None
        else:
            if not RNG:
                raise TypeError("A random-number generator function must be provided " + \
                                "as argument 'RNG' in order to create a new key. This must " + \
                                "be readable by direct call with an integer value, i.e. RNG(64), " + \
                                "and must return that number of bytes. If using RNGs that present " + \
                                "a file-like interface (i.e. RNG.read(64)), as for e.g. PyCrypto, " + \
                                "then pass the RNG.read method: Keypair(RNG=myRNG.read)")
            self.RNG = RNG
            if all_RNG:
                pass
            else:
                # Default behaviour without arguments.
                self.private_key, self.public_key, self.rng_secret = self.generate_hash_chain_key_pair(
                    preserve_secrets=True)

    def hash_function_digest(self, position, hash_fn_name=None):
        if hash_fn_name == "sha512":
            return sha512(position).digest()
        elif hash_fn_name == "sha256":
            return sha256(position).digest()

    def hash_function(self, hash_fn_name=None):
        if hash_fn_name == "sha512":
            return sha512()
        elif hash_fn_name == "sha256":
            return sha256()

    def _build_public_key(self, private_key=None, hash_fn_name=None):
        'Takes a list of value-pairs (lists or tuples), returns hash-pairs.'
        if not private_key:
            private_key = self.private_key

        def hash_pair(pair):
            return [self.hash_function_digest(pair[0], hash_fn_name), self.hash_function_digest(pair[1], hash_fn_name)]

        new_pubkey = []
        for private_pair in private_key:
            new_pubkey.append(hash_pair(private_pair))
        return new_pubkey

    def generate_hash_chain_key_pair(self, secret_seeds=None, hash_fn_name="sha512", hash_fn_length=512,
                                     preserve_secrets=False):

        # Generate a pair of large seeds for use in generating the private key hash-chain.
        if secret_seeds is None:
            secret_seeds = [self.RNG(1024), self.RNG(1024)]
        private_key = []

        prior_hashes = [self.hash_function_digest(pos, hash_fn_name) for pos in secret_seeds]
        for i in range(0, hash_fn_length):
            # Make new hash functions
            new_hashes = [self.hash_function(hash_fn_name), self.hash_function(hash_fn_name)]
            # Make room for the digests to be added to private_key
            append_hashes = []
            for i in range(0, 2):
                # Add prior hash for this position to new hash object:
                new_hashes[i].update(prior_hashes[i])
                # "Salt" the new hash with the secret seed for this position:
                new_hashes[i].update(secret_seeds[i])
                # Digest hash
                i_digest = new_hashes[i].digest()
                # Replace the (now used) prior hash with a new "prior hash"
                prior_hashes[i] = i_digest
                # Append the new digest to the append_hashes list: this will contain two hashes after this for-loop.
                append_hashes.append(i_digest)
            # Add the two new secret-salted hash-chain hashes to key list
            private_key.append(append_hashes)
        # Derive pubkey from private key
        public_key = self._build_public_key(private_key, hash_fn_name)

        if preserve_secrets:
            return private_key, public_key, secret_seeds
        else:
            # delete our secrets
            del (secret_seeds)
            return private_key, public_key, None

    def _exportable_key(self, key=None):
        export_key = []
        for unit in key:
            unit0 = self._bin_b64str(unit[0])
            unit1 = self._bin_b64str(unit[1])
            export_key.append([unit0, unit1])
        return export_key

    def _exportable_seed(self):
        export_seed = []
        unit0 = self._bin_b64str(self.rng_secret[0])
        unit1 = self._bin_b64str(self.rng_secret[1])
        export_seed.append([unit0,unit1])
        return export_seed

    def import_seed_only(self, secret_seed=None):
        secret_seed = json.load(secret_seed)
        key_seed = []
        unit0 = self._b64str_bin(secret_seed['seed'][0])
        unit1 = self._b64str_bin(secret_seed['seed'][1])
        key_seed.append([unit0, unit1])
        return key_seed


    def import_key_pair(self, key_pair=None):
        def parse_key(key):
            key_bin = []
            for unit_pair in key:
                unit0 = self._b64str_bin(unit_pair[0])
                unit1 = self._b64str_bin(unit_pair[1])
                key_bin.append([unit0, unit1])
            return key_bin

        if isinstance(key_pair, str):
            key_pair = json.loads(key_pair)
        elif not isinstance(key_pair, dict):
            raise TypeError("Only json-formatted strings or native dicts are supported for key import.")
        available_keys = key_pair.keys()
        if 'sec' in available_keys and 'pub' in available_keys:
            return parse_key(key_pair['sec']), parse_key(key_pair['pub'])
        elif 'sec' in available_keys:
            privkey = parse_key(key_pair['sec'])
            return privkey, self._build_public_key(privkey)

    def export_seed_only(self, file):
        with open(file, 'w') as jsonFile:
            json.dump({'seed': self._exportable_seed()}, jsonFile, indent=2)

    def export_key_pair(self, file):
        with open(file, 'w') as jsonFile:
            json.dump({'pub': self._exportable_key(self.public_key)}, jsonFile, indent=2)
            json.dump({'priv': self._exportable_key(self.private_key)}, jsonFile, indent=2)
            #Preco ked iterujem cez for je int, ale ked pristupujem ako prvok pola je str?
            json.dump({'seed': self._exportable_seed()}, jsonFile, indent=2)


def main():
    kluc = Keypair(RNG=RNG)
    kluc.export_key_pair("kluce.txt")
    # print(kluc.import_key_pair("kluce.txt"))          TODO: import klucov
    kluc.export_seed_only("seed.txt")
    # print(kluc.import_seed_only("seed.txt"))          TODO: import seedov

if __name__ == '__main__':
    main()
