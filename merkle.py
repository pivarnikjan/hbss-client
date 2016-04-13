# TODO cele prerobit
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
from ssl import RAND_bytes as RNG
from utils.hbss_utills import hash_function_digest

import lamport


class KeyManagementError(Exception):
    pass


class MerkleTree:
    @staticmethod
    def _bin_b64str(binary_stuff):
        'Utility method for converting bytes into b64-encoded strings.'
        return str(base64.b64encode(binary_stuff), 'utf-8')

    @staticmethod
    def _b64str_bin(b64_encoded_stuff):
        'Restores bytes data from b64-encoded strings.'
        return base64.b64decode(bytes(b64_encoded_stuff, 'utf-8'))

    def __init__(self, keynum=128, ExistingTree=None, hash_fn_name="sha512", hash_fn_length=512):
        self.private_keyring = []
        self.public_keyring = []
        self.public_hash = []
        self.hash_tree = [[]]
        self.used_keys = []
        self.hash_fn_name = hash_fn_name
        self.hash_fn_length = hash_fn_length

        if not ExistingTree:
            self._generate_hashchain_keypairs(keynum)
            self.generate_tree()

    def _generate_hashchain_keypairs(self, keynum):
        while keynum > 0:
            keynum -= 1
            newkey = lamport.keys_generation.Keypair(RNG=RNG)
            key_seed = newkey._exportable_seed()
            self.private_keyring.append(key_seed)
            self.public_keyring.append(self.tree_node_hash())
            self.hash_tree[0].append(self.tree_node_hash())

    def generate_tree(self):
        'Uses initial leaf values to populate hash-tree.'
        # Below: While the length of the last item in the hash tree is greater than 1 (i.e. not root)
        while len(self.hash_tree[len(self.hash_tree) - 1]) > 1:
            # Immediately create new empty list for new values.
            self.hash_tree.append([])
            # Tree depth so far, minus one so it can be used as a list index (starts at 0)
            tree_depth = len(self.hash_tree) - 1
            # For each of the hashes in the layer below the new empty one:
            for node_hash in self.hash_tree[tree_depth - 1][::2]:
                # Identify hash-pair at previous level to combine/hash:
                previous_node_index = self.hash_tree[tree_depth - 1].index(node_hash)
                brother_node_index = previous_node_index + 1
                previous_node = self.hash_tree[tree_depth - 1][previous_node_index]
                brother_node = self.hash_tree[tree_depth - 1][brother_node_index]
                # Generate new hash above these two hashes:
                new_node_hash = hash_function_digest((previous_node + brother_node), self.hash_fn_name)
                # Embed new hash "above" constitutent hashes in new layer:
                self.hash_tree[tree_depth].append(new_node_hash)

    def tree_node_hash(self, b64=False):
        # TODO figure out how to obtain public key
        flattened_pubkey = b''.join([b''.join(unitpair) for unitpair in self.public_key])
        merkle_node_hash = hash_function_digest(flattened_pubkey), self.hash_fn_name
        if b64:
            merkle_node_hash = self._bin_b64str(merkle_node_hash)
        return merkle_node_hash

    def _exportable_tree(self):
        exportable_tree = []
        for layer in self.hash_tree:
            exportable_tree.append([])
            for node_hash in layer:
                b64_str_hash = self._bin_b64str(node_hash)
                exportable_tree[len(exportable_tree) - 1].append(b64_str_hash)
        return exportable_tree

    def tree_public_key(self):
        'Returns the root node as a base-64 encoded string.'
        return (self.root_hash()[0])

    def root_hash(self):
        'Returns the root node as binary.'
        return self.hash_tree[len(self.hash_tree) - 1]

    def _sign_message(self, message, include_nodes=True,
                      include_pubkey=True, mark_used=True,
                      force_sign=False):

        KeyToUse = self.select_unused_key(mark_used=True, force=force_sign)
        signer = lamport.signature.Signer(KeyToUse)

        signature = {}
        signature["lamport_signature"] = signer.generate_signature(message)
        signature["lamport_verification_key"] = KeyToUse._exportable_key()
        signature["path"] = self.get_node_path(self.tree_node_hash())
        return signature

    def get_node_path(self, leaf_hash, cue_pairs=False, verify_nodes=True):

        if leaf_hash not in self.hash_tree[0]:
            raise KeyManagementError("Specified leaf_hash not in leaves" + \
                                     " of Merkle Tree. Hash requested was: " + \
                                     str(leaf_hash, 'utf-8'))
        node_list = []
        node_number = self.hash_tree[0].index(leaf_hash)
        level_num = 0
        for level in self.hash_tree:
            level_num += 1
            if level_num == len(self.hash_tree):
                break
            if node_number % 2:
                # i.e., if odd: so, use prior node as partner.
                if cue_pairs:
                    node_list.append([self._bin_b64str(level[node_number - 1]), None])
                else:
                    node_list.append(self._bin_b64str(level[node_number - 1]))
            else:
                # i.e., if even, so use next node as partner.
                if cue_pairs:
                    node_list.append([None, self._bin_b64str(level[node_number + 1])])
                else:
                    node_list.append(self._bin_b64str(level[node_number + 1]))
            # Get the node number for the next level of the hash-tree.
            # Oddly, using int() is faster than using math.floor() for
            # getting the pre-decimal value of a positive float.
            node_number = int(node_number / 2)
        if verify_nodes:
            pass
            # if not self.derive_root()
        return node_list

    def select_unused_key(self, mark_used=True, force=False):

        if len(self.used_keys) == len(self.hash_tree[0]) - 1:
            if not force:
                print("Only one key remains; you should use this key " + \
                      "to sign a new Merkle tree so as not to waste any trust signatures" + \
                      "accrued during the lifetime of this tree.")
                raise KeyManagementError("Only one key remains; you should use this key " + \
                                         "to sign a new Merkle tree so as not to waste any trust signatures" + \
                                         "accrued during the lifetime of this tree.")
        # Find an unused key by cycling through tree "leaves" and comparing
        # to a list of used leaves.
        counter = 0
        while self._is_used(self.hash_tree[0][counter]):
            counter += 1
        private_key = self.private_keyring[counter]
        if private_key is None:
            raise KeyManagementError(
                "Selected 'unused' key appears to have been used.")
        # Import key as a lamport Keypair.
        try:
            keypair = lamport.keys_generation.Keypair(private_seed=private_key)

        except IndexError as e:
            print("While attempting to create a keypair with the following:",
                  keypair, "..an error occurred:", e, sep="\r\n")
        # Check key to make sure it matches its leaf hash:
        try:
            assert (self.tree_node_hash() == self.hash_tree[0][counter])
        except AssertionError:
            raise KeyManagementError("Tree leaf node does not match keypair hash generated on-the-fly.")
        if mark_used:
            # Don't just mark it used, delete the key so it can't be used
            # again by accident!
            self.mark_key_used(self.tree_node_hash())
            self.private_keyring[counter] = None
        return keypair

    def mark_key_used(self, leaf_hash, delete_private=True):

        if leaf_hash not in self.used_keys:
            self.used_keys.append(leaf_hash)

    def _is_used(self, leaf_hash):
        if leaf_hash in self.used_keys:
            return True
        else:
            return False


def test():
    pass


if __name__ == '__main__':
    test()
