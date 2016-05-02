import time
timestamp = time.strftime("%Y%m%d-%H%M%S")

filename = 'signature.sig'
SIGNATURE_FILENAME = filename + timestamp
PRNG = 'SSL'
HASH_FUNCTION = 'sha512'
HASH_FUNCTION_LENGTH = 512
MERKLE_TREE_HEIGHT = 8
