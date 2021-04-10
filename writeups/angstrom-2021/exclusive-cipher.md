---
tags: crypto, xor
year: 2021
authors: crit
---
# Exclusive Cipher

*The key is 5 bytes long and the flag is somewhere in the message.*

Since the key is *only* 5 bytes long, and we know 5 characters of the flag, we can bruteforce it and pick the results apart.

There really is no science in this script:
```py
from binascii import *

known = b"actf{"

def xor(b, k):
    out = []
    k_idx = 0
    for c in b:
        out.append(c ^ k[k_idx])
        k_idx = (k_idx + 1) % len(k)
    return bytes(out)


with open("ciphertext.txt") as ct:
    enc = unhexlify(ct.read())
    for enc_idx in range(len(enc) - len(known)):
        key_candidate = b""
        for known_idx in range(len(known)):
            for byte in range(256):
                if known[known_idx] == enc[enc_idx + known_idx] ^ byte:
                    key_candidate += byte.to_bytes(1, "big")
                    break
        print(xor(enc, key_candidate))
```

You can simply run `python script.py | grep "actf{"` and read the few results.