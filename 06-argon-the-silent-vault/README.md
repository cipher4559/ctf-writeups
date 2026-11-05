# ARGON: The Silent Vault

| | |
|---|---|
| **Challenge ID** | `PAgWPeER` |
| **Category** | Cryptography |
| **Flag format** | `SOS{...}` |

## Premise

An archival signing appliance leaked "fragments of ephemeral hardware state"
through a diagnostic telemetry channel. We get the public key, 96 ECDSA
signatures, a binary diagnostic stream, an encrypted recovery bundle, and an
encrypted final vault. The intended chain is spelled out in the challenge:

> reconstruct the private signing scalar via lattice reduction, breach the
> recovery bundle, resolve the non-coprime common modulus RSA instance, derive
> the vault key, and unlock the final vault.

Argon2id and AES-256-GCM are used *correctly* — the bugs are in key generation
and in the RSA instance.

## Artifacts

```
f3debee966b3469b91ba26db0e1c49b4.zip
challenge.py        reference implementation / format documentation
public.json         public key, salts, channel map
signatures.jsonl    96 ECDSA signatures (id, message, r, s)
diagnostics.bin     7,680 bytes = 384 records x 20 bytes
recovery.enc        AES-256-GCM envelope
vault.enc           AES-256-GCM envelope (71 bytes)
```

## Step 1 — demultiplex the telemetry

Each 20-byte record is:

```
16 bytes  sig_id (UUID, matches signatures.jsonl)
 2 bytes  channel_id (big-endian)
 2 bytes  payload    (big-endian)
```

Channels: `0x0012` voltage, `0x0027` temperature, `0x008f` latency, and the
bug: **`0x0042` = upper 10 bits of the ECDSA nonce**, i.e. `h = k >> 246`.

96 signatures have a matching `0x0042` frame.

## Step 2 — ECDSA hidden-number attack

For a signature `(r, s)` over `z = SHA256(message)`:

```
s*k = z + r*d  (mod n)
k = s^-1*z + s^-1*r*d
```

With `k = h*2^246 + e`, `0 <= e < 2^246`, substitute:

```
s^-1*r*d + s^-1*z - h*2^246 = e   (mod n)
```

so

```
t_i * d + u_i = e_i,   |e_i| < 2^246
```

where `t_i = r_i * s_i^-1 mod n` and `u_i = z_i * s_i^-1 - h_i*2^246 mod n`.
This is a hidden-number problem with 246 unknown bits out of 256. With 96
samples (well above the ~30 needed at this leak rate), the standard lattice
with the `2^246` weighting recovers `d`:

```python
K = 1 << 246
# rows: -K*n on the diagonal, then [K*t_i], [K*u_i], 1
LLL.reduction(A)
# a row with last coordinate +/-1 gives d = row[-2] mod n
```

Check: `d*G == Q`.

Recovered private scalar:

```
d = 0x4793d79ca3bf6a2336b40e62cdff8519384c9bdf2aa4fb4a20c70ae963acd0d1
```

## Step 3 — open the recovery bundle

Per `challenge.py`:

```
IKM  = d.to_bytes(32, "big")
salt = wrap_salt = d45af3d931e645809d95d06201267889
info = b"ARGON/RECOVERY/v1"
K_wrap = HKDF-SHA256(IKM, salt, info, 32)
```

`recovery.enc` layout: `nonce[12] || tag[16] || ciphertext`, AAD
`ARGON/RECOVERY/v1`.

Decrypting yields a JSON payload with:

```
modulus_N, e1 = 196611, e2 = 300009, c1, c2
```

## Step 4 — common modulus with `gcd(e1, e2) = 3`

`gcd(e1, e2) = 3`, so extended GCD gives `a*e1 + b*e2 = 3`
(`a = -20737`, `b = 13590` in the solve). Then

```
c1^a * c2^b = m^3  (mod N)
```

The message `m` is 256 bits, so `m^3 < 2^768 < N`; the modular reduction never
wrapped and an **exact integer cube root** recovers `m`. The 32-byte token:

```
T = da25997f6e32dc2040c1c848e62829e9605a4226fa46e5814c22c9c
```

## Step 5 — Argon2id and the final vault

```
P = SHA256(b"ARGON/FINAL/v1" || d.to_bytes(32,"big") || T)
K_final = Argon2id(P,
                   salt = f998916ae4b80eaa8baa06f6ab8d44ef,
                   time_cost = 3,
                   memory_cost = 65536 KiB,
                   parallelism = 4,
                   hash_len = 32)
```

`vault.enc` uses the same envelope layout with AAD `ARGON/VAULT/v1`. AES-256-GCM
decryption of `vault.enc` with `K_final` yields the flag (the GCM tag validates
the whole chain).

## Tools & Methodology

**Tools:** Python 3, `fpylll` (LLL for the hidden-number lattice), HKDF-SHA256,
`cryptography` / PyCryptodome AES-GCM, `argon2-cffi`, integer cube root,
P-256 ECDSA verification.

**Method:**

1. Demultiplexed the 20-byte telemetry frames; channel `0x0042` leaked the top
   10 bits of each ECDSA nonce, giving 96 usable signatures.
2. Built the hidden-number lattice with `K = 2^246` weighting, LLL-reduced it,
   and recovered the private scalar `d`; checked `d*G == Q`.
3. HKDF-derived the recovery key from `d`, AES-GCM-decrypted `recovery.enc`, then
   solved the common-modulus RSA instance (`gcd(e1,e2)=3`) with an exact integer
   cube root to get the token.
4. Derived the final key with Argon2id (3 passes, 64 MiB, p=4) and AES-GCM
   decrypted `vault.enc`; the GCM tag validated the whole chain.

## Flag

```
SOS{argon_48cec92a70e93a55b4e232c2b8a733a9}
```

## Takeaway

Every layer except the "peripheral crypto" is sound. The break is a 10-bit
nonce leak — enough for a lattice HNP attack once enough signatures are
collected. Secondary issues:

* a recovery bundle keyed **directly** from the long-term signing scalar,
* an RSA instance with `gcd(e1, e2) = 3` and a message small enough that `m^3`
  does not wrap, permitting an exact integer root.

Nonce generation must be RFC 6979 deterministic or use a robust CSPRNG; never
mix "diagnostic" data into a channel that reveals nonce bits.
