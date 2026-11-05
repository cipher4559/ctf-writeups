# The Forgotten Vault

| | |
|---|---|
| **Challenge ID** | `9dEJPV1V` |
| **Category** | Cryptography |
| **Flag format** | `HACKITUP{...}` |

## Premise

A legacy vault uses AES-128-ECB. The key was derived following "Vault
Security Policy v2.1":

1. pick a dictionary word from `wordlist.txt`,
2. capitalise the first letter,
3. append a two-digit PIN (`00`–`99`),
4. compute `key = MD5(password)`.

We are given the ciphertext and the 5,460-word dictionary.

## Artifacts

```
0a3446a817d346bf955571cbae1843d0.zip   original attachment
challenge.py                            reference implementation
output.txt                              vault ciphertext (hex)
wordlist.txt                            5,460 candidate words
```

`output.txt`:

```
Vault Ciphertext (hex):
7baf12dccea4bd8d990332ccab34db81680f51ad006d3de122235e4f89ff55a35f23bd9f27ce8fe43806ed2df865f31f36ca319dabe533f22bee5a301f56cb75
```

## Analysis

The scheme leaks its entire key space. The password space is only

```
5460 words x 100 PINs = 546,000 candidates
```

and each candidate costs one MD5 plus one AES block decryption. There is no
salt, no KDF work factor, and no rate limit — the "security policy" compresses
a key space that should be ~2^128 into something a laptop exhausts in seconds.

Two implementation details matter:

* `format_password` uses `word.capitalize()`, so `vault` becomes `Vault`, then
  the PIN is appended with `:02d` — `Vault07`.
* `derive_key` does `md5(password.strip().encode())`, i.e. the raw 16-byte MD5
  digest is the AES key.

## Exploit

```python
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ct = bytes.fromhex(open("output.txt").read().splitlines()[1])

for word in open("wordlist.txt"):
    word = word.strip()
    if not word:
        continue
    for pin in range(100):
        pw = f"{word.capitalize()}{pin:02d}"
        key = hashlib.md5(pw.encode()).digest()
        d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        pt = d.update(ct) + d.finalize()
        # valid PKCS#7 padding + flag prefix
        if pt.startswith(b"HACKITUP{"):
            print(pw, pt)
```

First hit:

```
Keystone42 b'HACKITUP{md5_k3y_d3r1v4t10n_w1th_p1n_m4ngl1ng_15_f4r_t00_w34k}\x02\x02'
```

The `\x02\x02` is correct PKCS#7 padding for a 50-byte plaintext.

## Tools & Methodology

**Tools:** `unzip`/`7z` (attachment password `Keystone42`), Python 3
(`hashlib`, `zipfile`), PyCryptodome (`Crypto.Cipher.AES`), `xxd`.

**Method:**

1. Unpacked the attachment and read `challenge.py` / `output.txt` to reconstruct
   the key policy: `capitalize(word) + %02d PIN`, then `MD5(password)` as the
   AES-128 key.
2. Brute-forced the complete 5,460-word × 100-PIN keyspace (546,000 candidates),
   decrypting the vault ciphertext with AES-128-ECB for each key.
3. Filtered on valid PKCS#7 padding and printable plaintext, then confirmed the
   `HACKITUP{...}` value.

## Flag

```
HACKITUP{md5_k3y_d3r1v4t10n_w1th_p1n_m4ngl1ng_15_f4r_t00_w34k}
```

## Takeaway

Password "mangling" (capitalise + 2 digits) adds under 17 bits of entropy on
top of a 5,460-word dictionary. With an unsalted, fast hash (MD5) and ECB mode,
the whole construction collapses to an offline dictionary sweep. A slow KDF
(PBKDF2/scrypt/Argon2id), a random salt, and an authenticated mode (GCM) would
have made this infeasible.
