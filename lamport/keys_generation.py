# TODO doplnit komentare jednotlivych tried a metod
# TODO zistit ako zapisat do certifikatu, ze som to rozsiroval
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

from utils.hbss_utills import hash_function, hash_function_digest

try:
    from ssl import RAND_bytes as RNG
except ImportError:
    from Crypto import Random as RNG


class Keypair():
    @staticmethod
    def _bin_b64str(binary_stuff):
        'Shorthand: Converts bytes into b64-encoded strings.'
        return str(base64.b64encode(binary_stuff), 'utf-8')

    @staticmethod
    def _b64str_bin(b64_encoded_stuff):
        'Shorthand: Restores bytes data from b64-encoded strings.'
        return base64.b64decode(bytes(b64_encoded_stuff, 'utf-8'))

    def __init__(self, private_seed=None, key_data=None, RNG=None, hash_function="sha512", hash_fn_length=512,
                 all_RNG=False):

        self.hash_fn_name = hash_function
        self.hash_fn_length = hash_fn_length

        if private_seed:
            private_seed = private_seed
            self.private_key, self.public_key, self.rng_secret = self.generate_hash_chain_key_pair(private_seed)
        elif key_data:
            self.private_key, self.public_key = self._import_key_pair(key_data)
            self.rng_secret = None
        elif hash_function:
            self.RNG = RNG
            self.private_key, self.public_key, self.rng_secret = self.generate_hash_chain_key_pair(
                preserve_secrets=True)
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

    def _build_public_key(self, private_key=None):
        'Takes a list of value-pairs (lists or tuples), returns hash-pairs.'
        if not private_key:
            private_key = self.private_key

        def hash_pair(pair):
            return [hash_function_digest(pair[0], self.hash_fn_name), hash_function_digest(pair[1], self.hash_fn_name)]

        new_pubkey = []
        for private_pair in private_key:
            new_pubkey.append(hash_pair(private_pair))
        return new_pubkey

    def generate_hash_chain_key_pair(self, secret_seeds=None, preserve_secrets=False):

        # Generate a pair of large seeds for use in generating the private key hash-chain.
        if secret_seeds is None:
            secret_seeds = [self.RNG(1024), self.RNG(1024)]
        private_key = []

        prior_hashes = [hash_function_digest(pos, self.hash_fn_name) for pos in secret_seeds]
        for i in range(0, self.hash_fn_length):
            # Make new hash functions
            new_hashes = [hash_function(self.hash_fn_name), hash_function(self.hash_fn_name)]
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
        public_key = self._build_public_key(private_key)

        if preserve_secrets:
            return private_key, public_key, secret_seeds
        else:
            # delete our secrets
            del (secret_seeds)
            return private_key, public_key, None

    def _import_seed_from_file(self, jsonFile):
        with open(jsonFile, 'r') as data:
            secret_seed = json.load(data)
        key_seed = []
        unit0 = self._b64str_bin(secret_seed['seed'][0])
        unit1 = self._b64str_bin(secret_seed['seed'][1])
        key_seed.append([unit0, unit1])
        return key_seed

    def _exportable_seed(self):
        export_seed = []
        unit0 = self._bin_b64str(self.rng_secret[0])
        unit1 = self._bin_b64str(self.rng_secret[1])
        export_seed.append([unit0, unit1])
        return export_seed

    def export_seed_only(self, file):
        with open(file, 'w') as jsonFile:
            json.dump({'seed': self._exportable_seed()}, jsonFile, indent=2)

    def _import_key_pair(self, jsonFile):
        def parse_key(key):
            key_bin = []
            for unit_pair in key:
                unit0 = self._b64str_bin(unit_pair[0])
                unit1 = self._b64str_bin(unit_pair[1])
                key_bin.append([unit0, unit1])
            return key_bin

        with open(jsonFile, 'r') as data:
            key_pair = json.load(data)

        return parse_key(key_pair[0]['pub']), parse_key(key_pair[1]['priv'])

    def _exportable_key(self, key=None):
        export_key = []
        for unit in key:
            unit0 = self._bin_b64str(unit[0])
            unit1 = self._bin_b64str(unit[1])
            export_key.append([unit0, unit1])
        return export_key

    def export_public_key(self):
        return self._exportable_key(self.public_key)

    def export_key_pair(self, file):
        export_list = []
        export_list.append({'pub': self._exportable_key(self.public_key)})
        export_list.append({'priv': self._exportable_key(self.private_key)})
        # export_list.append({'seed': self._exportable_seed()})

        with open(file, 'w') as jsonFile:
            json.dump(export_list, jsonFile, indent=2)


def test():
    kluc = Keypair(RNG=RNG, hash_function="sha256", hash_fn_length=256)
    # kluc = Keypair(RNG=RNG)
    kluc.export_key_pair('keys.json')
    kluc.export_seed_only("seed.json")
    privatekey, publickey = kluc._import_key_pair('keys.json')


if __name__ == '__main__':
    test()
