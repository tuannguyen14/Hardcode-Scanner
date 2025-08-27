import json
import base58

# đọc file json keypair
with open("my-keypair.json", "r") as f:
    keypair = json.load(f)

# convert list -> bytes
keypair_bytes = bytes(keypair)

# encode sang base58 (full 64 byte)
private_key_base58 = base58.b58encode(keypair_bytes).decode()

print("Private Key (Base58):", private_key_base58)
