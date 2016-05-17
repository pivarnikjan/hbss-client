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
# TODO documentation

import base64
import json
from ssl import RAND_bytes as RNG
from utils.hbss_utills import hash_function_digest, exportable_key, exportable_key_single, importable_key_single, \
    importable_key, b64str_bin, bin_b64str

import lamport


class KeyManagementError(Exception):
    pass


class MerkleTree:
    # @profile
    def __init__(self, merkle_tree_height=8, PRNG=RNG, existing_tree=None, hash_function=("sha512", 512)):
        self.private_keyring = []
        self.public_keyring = []
        self.auth_path = []
        self.hash_tree = [[]]
        self.tree_height = merkle_tree_height
        self.used_keys = []
        self.signatures = []
        self.hash_fn_name = hash_function[0]
        self.hash_fn_length = hash_function[1]
        self.PRNG = PRNG

        if not existing_tree:
            self._generate_hashchain_keypairs()
            self.generate_tree()
        else:
            self.import_tree(existing_tree)
            # self.verify_tree()

    def tree_node_hash(self, public_key, b64=False):
        """

        Args:
            public_key:
            b64:

        Returns:

        """
        flattened_pubkey = b''.join([b''.join(unitpair) for unitpair in public_key])
        merkle_node_hash = hash_function_digest(flattened_pubkey, self.hash_fn_name)
        if b64:
            merkle_node_hash = bin_b64str(merkle_node_hash)
        return merkle_node_hash

    def _generate_hashchain_keypairs(self):
        """

        Returns:

        """
        keynum = 2 ** self.tree_height

        while keynum > 0:
            keynum -= 1
            newkey = lamport.keys_generation.Keypair(RNG=self.PRNG, hash_fn=[self.hash_fn_name, self.hash_fn_length])
            self.private_keyring.append(newkey.rng_secret)
            self.public_keyring.append(self.tree_node_hash(newkey.public_key, b64=True))
            self.hash_tree[0].append(self.tree_node_hash(newkey.public_key))

    # @profile
    def generate_tree(self):
        """

        Returns:

        """
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

    def root_hash(self):
        """

        Returns:

        """
        'Returns the root node as binary.'
        return bin_b64str(self.hash_tree[-1][0])

    # @profile
    def generate_authentication_path(self, leaf_hash):
        """

        Args:
            leaf_hash:

        Returns:

        """
        authentication_path = []

        index_s = self.hash_tree[0].index(leaf_hash)

        for i in range(self.tree_height):
            tmp = index_s // (2 ** i)
            if tmp % 2 == 1:
                authentication_path.append(bin_b64str(self.hash_tree[i][tmp - 1]))
            elif tmp % 2 == 0:
                authentication_path.append(bin_b64str(self.hash_tree[i][tmp + 1]))

        return authentication_path

    def mark_key_used(self, leaf_hash):
        """

        Args:
            leaf_hash:

        Returns:

        """
        if leaf_hash not in self.used_keys:
            self.used_keys.append(leaf_hash)

    def _is_used(self, leaf_hash):
        """

        Args:
            leaf_hash:

        Returns:

        """
        if leaf_hash in self.used_keys:
            return True
        else:
            return False

    def select_unused_key(self, mark_used=True, force=False):
        """

        Args:
            mark_used:
            force:

        Returns:

        """
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

        if not private_key:
            raise KeyManagementError(
                "Selected 'unused' key appears to have been used.")
        # Import key as a lamport Keypair.
        try:
            keypair = lamport.keys_generation.Keypair(RNG=self.PRNG, private_seed=private_key,
                                                      hash_fn=[self.hash_fn_name, self.hash_fn_length])

        except IndexError as e:
            print("While attempting to create a keypair with the following:",
                  keypair, "..an error occurred:", e, sep="\r\n")
        # Check key to make sure it matches its leaf hash:
        try:
            assert (self.tree_node_hash(keypair.public_key) == self.hash_tree[0][counter])
        except AssertionError:
            raise KeyManagementError("Tree leaf node does not match keypair hash generated on-the-fly.")
        if mark_used:
            # Don't just mark it used, delete the key so it can't be used
            # again by accident!
            self.mark_key_used(private_key)
            self.private_keyring[counter] = []
        return keypair

    def sign_message(self, message, force_sign=False):
        """

        Args:
            message:
            force_sign:

        Returns:

        """
        KeyToUse = self.select_unused_key(mark_used=True, force=force_sign)
        signer = lamport.signature.Signer(KeyToUse, self.hash_fn_name)

        signature = {}
        generated_signature = signer.generate_signature(message)
        signature["sig"] = exportable_key_single(generated_signature)
        signature["vrfy"] = KeyToUse.export_public_key()
        signature["pub"] = self.root_hash()
        self.auth_path = self.generate_authentication_path(self.tree_node_hash(KeyToUse.public_key))
        signature["path"] = self.auth_path
        self.signatures.append(signature)

        return signature

    def _verify_key_pair(self, signature_list, message):
        """

        Args:
            signature_list:
            message:

        Returns:

        """
        def import_signature(signature):
            with open(signature, 'r') as json_file:
                sig = json.load(json_file)
            vrfy = sig['sig']
            list_vrfy = importable_key_single(vrfy)
            return list_vrfy

        verification = lamport.verification.Verifier(signature_list, self.hash_fn_name)
        result = verification.verify_signature(import_signature(signature_list), message)
        return result

    def _concat_function(self, list_of_values):
        """

        Args:
            list_of_values:

        Returns:

        """
        new_list = []
        decoded_string = [base64.b64decode(item) for item in list_of_values]
        joined_string = b''.join(decoded_string)
        digest = hash_function_digest(joined_string, self.hash_fn_name)
        new_list.append(base64.b64encode(digest))
        return new_list

    def concatenate_children(self, children1, children2):
        """

        Args:
            children1:
            children2:

        Returns:

        """
        return hash_function_digest(children1 + children2, self.hash_fn_name)

    def _verify_authentication_path(self, index_s, p_0, auth_path, tree_height):
        """

        Args:
            index_s:
            p_0:
            auth_path:
            tree_height:

        Returns:

        """
        p_h = p_0

        for i in range(tree_height):
            tmp = index_s // (2 ** i)
            if tmp % 2 == 1:
                p_h = self.concatenate_children(auth_path[i], p_h)
            elif tmp % 2 == 0:
                p_h = self.concatenate_children(p_h, auth_path[i])
        return p_h

    def verify_message(self, signature_file, message):
        """

        Args:
            signature_file:
            message:

        Returns:

        """
        with open(signature_file, 'r') as json_file:
            signature = json.load(json_file)

        vrfy = signature['vrfy']
        path = signature['path']

        import_vrfy = importable_key(vrfy)
        single_node = self.tree_node_hash(import_vrfy)
        new_path = importable_key_single(path)
        index_s = self.public_keyring.index(bin_b64str(single_node))

        if not self._verify_key_pair(signature_file, message):
            return False
        elif not self._verify_authentication_path(index_s, single_node, new_path, len(self.hash_tree[-1])):
            return False
        else:
            return True

    def _exportable_tree(self):
        """

        Returns:

        """
        exportable_tree = []
        for layer in self.hash_tree:
            exportable_tree.append([])
            for node_hash in layer:
                b64_str_hash = bin_b64str(node_hash)
                exportable_tree[-1].append(b64_str_hash)
        return exportable_tree

    @staticmethod
    def _importable_tree(tree):
        """

        Args:
            tree:

        Returns:

        """
        importable_tree = []
        for layer in tree:
            importable_tree.append([])
            for node_hash in layer:
                bin_hash = b64str_bin(node_hash)
                importable_tree[-1].append(bin_hash)
        return importable_tree

    def export_tree(self, passphrase=None):
        """

        Args:
            passphrase:

        Returns:

        """
        # Desired features include a symmetric encryption function.
        tree = {'public_keys': self.public_keyring,
                'private_keys': exportable_key(self.private_keyring),
                'merkle_tree': self._exportable_tree(),
                'signatures': self.signatures,
                'used_keys': exportable_key(self.used_keys),
                'hash_fn_name': self.hash_fn_name,
                'hash_fn_length': self.hash_fn_length}
        return tree

    def import_tree(self, tree_file):
        """

        Args:
            tree_file:

        Returns:

        """
        with open(tree_file, 'r') as jsonFile:
            tree = json.load(jsonFile)

        self.public_keyring = tree['public_keys']
        self.private_keyring = importable_key(tree['private_keys'])
        self.hash_tree = self._importable_tree(tree['merkle_tree'])
        self.signatures = tree['signatures']
        self.used_keys = importable_key(tree['used_keys'])
        self.hash_fn_name = tree['hash_fn_name']
        self.hash_fn_length = tree['hash_fn_length']


# @profile
def test():
    tree = MerkleTree(2, hash_function=["sha256", 256])
    # tree = MerkleTree(2)

    mysig = tree.sign_message("johny".encode('utf-8'))
    # try:
    #     mysig = tree.sign_message("dano".encode('utf-8'))
    # except KeyManagementError:
    #     new_tree = tree.create_new_tree(tree)
    #     tree = new_tree
    #     mysig = tree.sign_message("dano".encode('utf-8'))

    with open("signature.json", mode='w') as SigOut:
        SigOut.write(json.dumps(mysig, indent=2))

    # --- VERIFY PART ---
    verify = tree.verify_message("signature.json", "dano".encode('utf-8'))
    print(verify)

    data = tree.export_tree()
    with open('merkle_tree.json', 'w') as f:
        f.write(json.dumps(data, f, indent=2))

    tree = MerkleTree(existing_tree="merkle_tree.json")
    verify = tree.verify_message("signature.json", "johny".encode('utf-8'))
    print(verify)


if __name__ == '__main__':
    test()
