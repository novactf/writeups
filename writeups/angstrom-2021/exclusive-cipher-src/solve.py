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
