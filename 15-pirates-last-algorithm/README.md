# Pirate's Last Algorithm

| | |
|---|---|
| **Challenge ID** | `XeE8Qby8` |
| **Category** | Reverse Engineering |
| **Flag format** | `HACKITUP{...}` |

## Premise

Captain Bartholomew "Blackthorn" Vance locked his treasury with the **Dead Man's
Astrolabe**, a mechanical automaton that demands an authorization key "calibrated
to the navigational runes of his final voyage". The quartermaster's journal warns:

> *"The captain never trusted a single compass. Three turns of the wheel decide
> the voyage, and the Dead Man's Astrolabe charts the only safe passage through
> the cursed shoals. One false bearing, and the vault locks forever in the abyss."*

"Three turns of the wheel" is a hint at the **three constants** of a linear
congruential generator.

## Artifact

```
32470896d7b04ff69adaf885c4d77e45.zip
blackthorn_vault.exe    PE32, i386, MinGW (gcc), 12 sections
```

## Static analysis

`strings` immediately shows the programme's shape:

```
BLACKTHORN'S FORGOTTEN VAULT
Captain's authorization key:
[!] The vault rejects your silence.
[!] The astrolabe will not turn: malformed inscription.
FLAG: %s
[!] The vault rejects your offering.
blackthorn_vault.c
_g_astrolabe_program
_g_vault_ciphertext
```

Two globals matter: `_g_astrolabe_program` (the LCG parameters) and
`_g_vault_ciphertext` (the encrypted flag). The binary is unoptimised MinGW debug
code, so `objdump -d` / a decompiler exposes the `main` logic cleanly:

* read the "authorization key" from stdin,
* run a **linear congruential generator** (LCG) seeded from it,
* XOR the ciphertext with the LCG's high byte,
* print `FLAG: <plaintext>` only if the result looks valid.

The LCG is the standard glibc/MSVC one:

```
state = seed
state = state * 0x41c64e6d + 0x3039   (mod 2^32)
key_byte = (state >> 16) & 0xff
```

The seed is the constant `0xf2a1c0dd` (the "authorization key" the astrolabe
expects). The ciphertext blob is 51 bytes in `.rdata` at file offset `0x1ca0`:

```
d852afb539be4b91cb05a1e7e28d125156d10a4e092e6d7ae77fa418ebb26c40
9187b6f0160347dc33bd7e56fba8825efa9137
```

## Exploit

```python
data = open("blackthorn_vault.exe", "rb").read()

ct = bytes.fromhex(
    "d852afb539be4b91cb05a1e7e28d125156d10a4e092e6d7ae77fa418ebb26c40"
    "9187b6f0160347dc33bd7e56fba8825efa9137")
assert data.find(ct) == 0x1ca0

state = 0xf2a1c0dd
out = bytearray()
for b in ct:
    state = (state * 0x41c64e6d + 0x3039) & 0xffffffff
    out.append(b ^ ((state >> 16) & 0xff))

print(out.decode())
```

Output:

```
HACKITUP{b14ckth0rn_v4u1t_c04st41_4str014b3_m4st3r}
```

Note the LCG is stepped **before** each output byte (`pre` order) and the key is
the **third** byte (bits 16–23) of the 32-bit state, not the low byte. Both details
matter — using `state & 0xff` or stepping after produces garbage.

## Tools & Methodology

**Tools:** `file`, `strings`, `objdump -d`/`pefile`, Python 3 (LCG
reimplementation), `xxd`.

**Method:**

1. Identified `blackthorn_vault.exe`, located the encrypted blob, and recovered
   the LCG parameters (`seed=0xf2a1c0dd`, `state = state*0x41c64e6d + 0x3039`)
   from the disassembly.
2. Reimplemented the generator, advanced it in lockstep with the blob at
   `0x1ca0`, and XORed the high byte of each state with the ciphertext.
3. Recognized the `HACKITUP{...}` plaintext and cross-checked the keystream
   against the static disassembly.

## Flag

```
HACKITUP{b14ckth0rn_v4u1t_c04st41_4str014b3_m4st3r}
```

## Takeaway

A single 32-bit LCG with a **hard-coded seed** provides zero secrecy: the
ciphertext and the generator constants are both in the binary, so the keystream is
reproducible offline. "Three turns of the wheel" literally encoded the three LCG
constants (`multiplier`, `increment`, `modulus`). Any stream cipher whose state is
seeded from a constant in the executable is just obfuscation.
