import time
timestamp = time.strftime("%Y%m%d-%H%M%S")

filename = 'signature-'
SIGNATURE_FILENAME = filename + timestamp + '.sig'
PRNG = 'SSL'
HASH_FUNCTION = 'sha512'
HASH_FUNCTION_LENGTH = 512
MERKLE_TREE_HEIGHT = 8
