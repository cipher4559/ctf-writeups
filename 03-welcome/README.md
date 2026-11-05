# Welcome

| | |
|---|---|
| **Challenge ID** | `QkEYjNyG` |
| **Category** | Cryptography |
| **Flag format** | `SOS{...}` |

## Premise

A recovered pirate transmission is "nothing more than a meaningless sequence
of characters", with one clue:

> *The truth is hidden in the alphabets, not in the words.*

That phrasing points at **base encodings**: the same characters mean different
values depending on which alphabet (base62 variant, base58 variant, base32)
you decode them with.

## Artifact

The challenge supplies only the ciphertext string:

```
3HZF7u0WE87LVnejqUQ6yIymxYd4LYh6YqJieV2Oft7iYaggfjl6I93nrGF3N6kEWhTNCdnfjCVuROFAA4sWX7kod
```

## Analysis

A blind multi-base BFS over the usual alphabets is enough. The solver tries,
at each node:

* base62 decodings with four common alphabets (`0-9A-Za-z`, `A-Za-z0-9`,
  `a-zA-Z0-9`, `0-9a-zA-Z`),
* base58 with the Bitcoin, Ripple and Flickr alphabets,
* base36,
* ASCII transforms (reverse, ROT13),

keeps every output that is printable ASCII and shorter than 300 bytes, and
searches for `SOS{` / `FLAG{`.

The unique successful path is three layers deep:

```
base62 (0-9A-Za-z)
  -> base58 (Bitcoin alphabet)
    -> base32 (RFC 4648)
```

Intermediate values (verified by re-running the solver):

```
input       3HZF7u0WE87LVnejqUQ6yIymxYd4LYh6YqJieV2Oft7iYaggfjl6I93nrGF3N6kEWhTNCdnfjCVuROFAA4sWX7kod
base62 std  3mDj8fUq2nVY4SKHQoVgv4c9AMmrStjJi16dPeWfJ58rzQxJf4MRpKsDjtVGdsFm7S
base58 btc  KNHVG62XMVWGG33NMVPWEYLEMR4V653FNRWF64DMMF4WKZD5
base32      SOS{Welcome_baddy_well_played}
```

Note the clever trap: decoding the original as base58 directly produces
garbage, and the second layer's output only looks like a valid base32 string
once you use the *Bitcoin* base58 alphabet (`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`,
notably missing `0 O I l`). Choosing the wrong base58 alphabet dead-ends.

## Solver (excerpt)

```python
import base64

b62_std = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
b58_btc = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def dec_base(t, alph):
    n = 0
    for c in t:
        n = n * len(alph) + alph.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

s1 = dec_base(CT, b62_std).decode()
s2 = dec_base(s1, b58_btc).decode()
print(base64.b32decode(s2).decode())
```

## Tools & Methodology

**Tools:** Python 3, custom base62/base58 decoders (Bitcoin alphabet), base32
decoder, CyberChef for cross-checking.

**Method:**

1. Decoded the supplied string with the base62 alphabet (`0-9A-Za-z`).
2. Re-decoded the resulting bytes with base58 using the Bitcoin alphabet.
3. Base32-decoded the next layer and validated the printable `SOS{...}` result.

## Flag

```
SOS{Welcome_baddy_well_played}
```

## Takeaway

"Hidden in the alphabets" means the encoding layer, not the content. When a
string is composed only of `[0-9A-Za-z]`, always try multiple base-alphabet
variants — base62 and base58 are ambiguous without knowing the alphabet, and
base encodings are frequently chained.
