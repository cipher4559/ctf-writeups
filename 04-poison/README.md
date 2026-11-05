# Poison

| | |
|---|---|
| **Challenge ID** | `D61QlDyG` |
| **Category** | Cryptography |
| **Flag format** | `flag{...}` |

## Premise

An ElGamal encryption scheme over **NIST P-192 (secp192r1)** is implemented on
hardware whose decryption module "suffers from bit flips". We are given the
public transcript of many faulty decryptions and must recover the master
secret key — which is the flag encoded as an integer.

## Artifacts

```
4de77d8b4ceb41958d90e717e5e63ab6.zip
chall.py / chall.sage    reference implementations
out.txt                  ms, C1s, C2s, decs — 319 records
```

## The scheme and the fault

For each bit of the private scalar `priv` (319 bits for the 40-byte flag), the
challenge:

```
k   <- random
M   <- random curve point
C1  = k*G
C2  = M + k*Q            (Q = priv*G)
```

and then decrypts with a **faulty** private key:

```
faulty_priv = priv with ONE bit flipped
dec         = C2 - faulty_priv*C1
```

Because `C2 - priv*C1 = M`, the faulty result is directly related to `M`:

```
dec = M + k*(priv - faulty_priv)*G
    = M ± 2^w * C1
```

where `w` is the bit weight of the flipped bit. So for every record we know
`M`, `C1` and `dec`, and can decide between two candidates:

```
if dec == M - 2^w * C1:  the original bit was 0  (0 -> 1 flip)
if dec == M + 2^w * C1:  the original bit was 1  (1 -> 0 flip)
```

## The index/weight gotcha

`chall.py` flips **string characters** of `bin(priv)[2:]`, not integer bit
positions:

```python
ind = total_bits - 1 - count
faulty_priv = int(poison(priv_bin, ind), 2)
```

String index `0` is the MSB, so record `count` flips the bit with value
`2**count`, i.e. the records expose the private scalar **LSB first**. Recover
the 319 bits, then reverse the list before reconstructing the integer. (This is
the "decoded bits in reverse order" trap noted during the event; using
`2**ind` instead of `2**count` matches only 1 of 319 records.)

## Solver (verified)

```python
import ast, re
from math import *
# ... parse ms, C1s, C2s, decs from out.txt ...

p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc

def add(P, Q): ...
def sub(P, Q): return add(P, (Q[0], (-Q[1]) % p))
def mul(k, P): ...

lsb_first = []
for count, (M, C1, C2, dec) in enumerate(zip(ms, C1s, C2s, decs)):
    step = mul(1 << count, C1)          # NOT 1 << (len-1-count)
    if   dec == sub(M, step): lsb_first.append("0")
    elif dec == add(M, step): lsb_first.append("1")
    else: raise ValueError("unexpected")

bits = "".join(reversed(lsb_first))      # back to MSB-first
priv = int(bits, 2)
print(priv.to_bytes((priv.bit_length()+7)//8, "big"))
```

Output:

```
b'flag{p01s0n3d_3cc_f4u1t_4tt4ck_succ3ss!}'
```

All 319 records resolve cleanly, which also confirms the bit ordering.

## Tools & Methodology

**Tools:** Python 3 (P-192 point arithmetic), `ast`/regex parser for `out.txt`,
SageMath for an independent curve check.

**Method:**

1. Parsed every fault record (`M`, `C1`, `C2`, `dec`) and modelled the ElGamal
   decryption with exactly one flipped private-key bit.
2. For record number `count`, computed the differential `M - dec` and matched it
   against `±2^count · C1` to decide whether the original bit was 0 or 1.
3. Because `chall.py` indexes the binary string, collected the bits LSB-first,
   reversed them to MSB-first, rebuilt the 319-bit scalar, and decoded the flag.
   All 319 records resolved, validating the bit order.

## Flag

```
flag{p01s0n3d_3cc_f4u1t_4tt4ck_succ3ss!}
```

## Takeaway

A single-bit fault in a scalar multiplication leaks that bit of the scalar
when the corresponding plaintext is known. Repeating the fault for every bit
turns a 192-bit key into a trivial comparison problem. Fault injection
countermeasures (scalar blinding, point verification, recomputation with the
public exponent) exist precisely for this class of attack.
