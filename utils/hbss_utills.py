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

from hashlib import sha512, sha256, sha384
import base64
from utils import bitstring


# TODO: zistit ako spravit return pre meniaci sa nazov funkcie - dict?
# TODO: documentation

def calculate_hash_from_file(afile, hasher, blocksize=65536):
    """

    Args:
        afile:
        hasher:
        blocksize:

    Returns:

    """
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.digest()


def hash_function_digest(position, hash_fn_name):
    """

    Args:
        position:
        hash_fn_name:

    Returns:

    """
    if hash_fn_name == "sha512":
        return sha512(position).digest()
    elif hash_fn_name == "sha256":
        return sha256(position).digest()
    elif hash_fn_name == "sha384":
        return sha384(position).digest()


def hash_function(hash_fn_name):
    """

    Args:
        hash_fn_name:

    Returns:

    """
    if hash_fn_name == "sha512":
        return sha512()
    elif hash_fn_name == "sha256":
        return sha256()
    elif hash_fn_name == "sha384":
        return sha384()


def bin_b64str(binary_stuff):
    """
    Converts bytes into b64-encoded strings.

    Args:
        binary_stuff:

    Returns: b64-encoded strings
    """
    return str(base64.b64encode(binary_stuff), 'utf-8')


def b64str_bin(b64_encoded_stuff):
    """
    Restores bytes data from b64-encoded strings.

    Args:
        b64_encoded_stuff:

    Returns: bytes
    """
    return base64.b64decode(bytes(b64_encoded_stuff, 'utf-8'))


def exportable_key(key):
    """

    Args:
        key:

    Returns:

    """

    export_key = []
    for unit in key:
        if unit:
            unit0 = bin_b64str(unit[0])
            unit1 = bin_b64str(unit[1])
            export_key.append([unit0, unit1])
        else:
            export_key.append([])
    return export_key


def exportable_key_single(key):
    """

    Args:
        key:

    Returns:

    """
    export_key = []
    for unit in key:
        export_key.append(bin_b64str(unit))
    return export_key


def importable_key(key):
    """

    Args:
        key:

    Returns:

    """
    import_key = []
    for unit in key:
        if unit:
            unit0 = b64str_bin(unit[0])
            unit1 = b64str_bin(unit[1])
            import_key.append([unit0, unit1])
        else:
            import_key.append([])
    return import_key


def importable_key_single(key):
    """

    Args:
        key:

    Returns:

    """
    import_key = []
    for unit in key:
        import_key.append(b64str_bin(unit))
    return import_key


def bit_hash(message_hash):
    """

    Args:
        message_hash:

    Returns:

    """
    'Returns a list of bools representing the bits of message_hash'
    if not isinstance(message_hash, bytes):
        raise TypeError(("message_hash must be a binary hash, "
                         "as returned by *.digest()"))
    hash_bits = bitstring.BitString(message_hash)
    # There is a reason we're converting booleans (low-memory usage)
    # to ints (probably higher memory usage): the values for each
    # bit will be used as list indices for selecting which pubkey hash
    # or private key number to use when signing and verifying.
    # TODO: Run some comparisons and performance checks
    #       to see if it's faster to use booleans and if/else clauses instead.
    return [int(x) for x in list(hash_bits.bin)]
