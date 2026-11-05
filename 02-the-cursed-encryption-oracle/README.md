# The Cursed Encryption Oracle

| | |
|---|---|
| **Challenge ID** | `O2gGnW19` |
| **Category** | Cryptography |
| **Flag format** | `flag{...}` |
| **Live service** | https://cursed-encryption-oracle.vercel.app |

## Premise

A "cursed cipher device" encrypts whatever you whisper into it, then appends
the captain's secret coordinates and seals the result. Old sea tales spell out
the flaw in plain language:

> *"The curse is rigid—it processes the tides in fixed marches of 16 strides.
> Repeat the exact incantation, and the exact same seal shall emerge... Shift
> your whisper by but a single grain of sand, and the beast might just reveal
> its secret."*

That is a textbook description of **AES-ECB with a fixed secret suffix** — the
setup for a byte-at-a-time ECB chosen-plaintext attack.

## Interface

The oracle exposes `POST /encrypt`, taking the plaintext as a JSON **string**
(not hex) in the field `plaintext`, and returns the per-block ciphertext:

```bash
curl -s -X POST https://cursed-encryption-oracle.vercel.app/encrypt \
     -H 'Content-Type: application/json' \
     -d '{"plaintext":"AAAA"}'
# {"block_count":3,
#  "blocks":["b9ea...","c1df...","4eea..."],
#  "ciphertext":"b9ea...c1df...4eea...",
#  "input_length":4}
```

The plaintext layout is:

```
user_input || SECRET
```

where `SECRET` is the flag, 42 characters plus a trailing newline (43 bytes
total), and the whole thing is PKCS#7-padded to 16-byte blocks. The total length
is measurable: `block_count` rises from 3 to 4 when the input reaches 6 bytes,
and from 4 to 5 at 22 bytes, which pins `len(SECRET) = 43`.

## Why ECB leaks the secret

ECB encrypts every 16-byte block independently:

```
E(P1) || E(P2) || ... || E(Pn)
```

If two plaintext blocks anywhere in the message are equal, their ciphertext
blocks are equal. By controlling the length of `user_input` we can slide the
unknown secret bytes into a block whose other 15 bytes we already know, then
dictionary-test all 256 possible values for the unknown byte against a
reference encryption of those same 15 bytes.

## Attack

Standard byte-at-a-time ECB:

1. Determine block size: send increasing lengths of `A` and watch when the
   ciphertext length jumps by 16. Block size = 16.
2. Determine the secret length: align the suffix so the last block is pure
   padding; the number of secret bytes follows from the total length.
3. For `i = 0 .. len(secret)-1`:
   * send `A` repeated `(15 - i mod 16)` times so the next unknown secret byte
     is the **last** byte of a block;
   * the preceding `i` secret bytes plus filler form the known prefix;
   * send the same prefix + each candidate byte `c ∈ [0,255]` and compare the
     first ciphertext block;
   * the matching `c` is the next secret byte.

Reference implementation used during the event (reproduced below):

```python
import json, urllib.request

URL = "https://cursed-encryption-oracle.vercel.app/encrypt"

def enc(s: str) -> list[bytes]:
    req = urllib.request.Request(
        URL, data=json.dumps({"plaintext": s}).encode(),
        headers={"Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=20))
    return [bytes.fromhex(b) for b in r["blocks"]]

BS = 16
secret = ""
for i in range(64):
    pad = "A" * (BS - 1 - (i % BS))
    target = enc(pad)[i // BS]                 # block that ends on secret[i]
    for c in range(256):
        if enc(pad + secret + chr(c))[i // BS] == target:
            secret += chr(c)
            break
    if secret.endswith("}"):
        break
print(secret)
```

A faster confirmation for already-known bytes: with `pad = "A"*(15-(i%16))`,
`enc(pad)[i//16] == enc(pad + secret[:i] + secret[i])[i//16]` must hold.

Because the secret is appended *after* the user input, no prefix stripping is
needed; the known-prefix block is entirely attacker-controlled.

## Recovered secret

```
flag{d3ad_m3ns_t3ll_n0_ta1l5_but_ECB_d03s}
```

(42 characters + newline, matching the challenge's stated length.)

## Tools & Methodology

**Tools:** `curl`, Python 3 (`requests`/`json`), browser DevTools, PyCryptodome
(offline block checks).

**Method:**

1. Probed the live oracle `/encrypt` endpoint with chosen-length plaintexts and
   compared ciphertext blocks; equal plaintext blocks produced equal ciphertext,
   confirming ECB mode and a fixed appended secret.
2. Ran a byte-at-a-time ECB attack: padded the input so the next secret byte was
   the last byte of a block, replayed the preceding block as a lookup dictionary,
   and tested all 256 candidates.
3. Repeated for the full 42-byte secret and submitted the assembled `flag{...}`.

## Flag

```
flag{d3ad_m3ns_t3ll_n0_ta1l5_but_ECB_d03s}
```

## Takeaway

ECB mode plus a secret suffix is a deterministic codebook: equal plaintext
blocks produce equal ciphertext blocks. Any adaptive chosen-plaintext oracle
therefore becomes a byte-by-byte decryption oracle. The fix is an authenticated
mode with a random nonce (GCM/ChaCha20-Poly1305), or at minimum CBC with a
random IV and a MAC — never a raw block cipher over `input || secret`.
