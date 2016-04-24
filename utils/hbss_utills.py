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

from hashlib import sha512, sha256, sha384
import base64
from utils import bitstring


# TODO: zistit ako spravit return pre meniaci sa nazov funkcie - dict?

def calculate_hash_from_file(afile, hasher, blocksize=65536):
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.digest()


def hash_function_digest(position, hash_fn_name):
    if hash_fn_name == "sha512":
        return sha512(position).digest()
    elif hash_fn_name == "sha256":
        return sha256(position).digest()


def hash_function(hash_fn_name):
    if hash_fn_name == "sha512":
        return sha512()
    elif hash_fn_name == "sha256":
        return sha256()


def _bin_b64str(binary_stuff):
    'Shorthand: Converts bytes into b64-encoded strings.'
    return str(base64.b64encode(binary_stuff), 'utf-8')


def _exportable_key(key):
    export_key = []
    for unit in key:
        if unit:
            unit0 = _bin_b64str(unit[0])
            unit1 = _bin_b64str(unit[1])
            export_key.append([unit0, unit1])
        else:
            export_key.append([])
    return export_key


def _exportable_key_single(key):
    export_key = []
    for unit in key:
        export_key.append(_bin_b64str(unit))
    return export_key


def bit_hash(message_hash):
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
    # TODO: to see if it's faster to use booleans and if/else clauses instead.
    return [int(x) for x in list(hash_bits.bin)]
