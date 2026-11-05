# The Cursed APK

| | |
|---|---|
| **Challenge ID** | `5jEzQ8gr` |
| **Category** | Mobile Security |
| **Flag format** | `FLAG{...}` |

## Premise

A rugged maritime phone recovered from a pirate vessel runs **Cursed Vault**
(`com.cursed.vault`). The vault's warning is literal: *"The vault does not open
for those who merely read its code."* Static strings show a "flag", but the triage
notes confirm it is a honeypot that the score server rejects. The app also
plants **emulator** and **root** detectors ("sentries") that must be bypassed, and
the real path is the verification math behind the sea oath.

## Artifacts

```
bb838db668ed4abd9ad0645bb4b16d72.zip
the-cursed-apk-player/cursed-vault.apk
the-cursed-apk-player/evidence/triage_notes.txt
the-cursed-apk-player/evidence/recovered_device_memo.txt
the-cursed-apk-player/apk_manifest.txt
```

Triage notes state explicitly that the obvious `FLAG{...}` string is a decoy
(`INCORRECT FLAG` on the score server) and that runtime checks gate the vault.

## Step 1 — decompile and map the checks

```bash
jadx -d cursed cursed-vault.apk
```

Relevant pieces:

* `isEmulator(Context)` — Build.* / sensor / file heuristics.
* root checks — `su` binaries, test-keys, writable `/system`.
* a *device token* that changes when either sentry fires.
* `getSeaOath()` — reconstructs the oath from two obfuscated arrays.

## Step 2 — reconstruct the sea oath

`getSeaOath()` assembles the string from constants:

```java
byte[] bArr = {30,31,27,30,5,23,31,20,5};      // XOR 90
String cArr2 = "TELL_NO_";
int[]  iArr = {134,115,126,119,133,145,99,105,99,106};  // minus 50
```

```python
part1 = ''.join(chr(b ^ 90) for b in [30,31,27,30,5,23,31,20,5])
# 'DEAD_MEN_'
part2 = 'TELL_NO_'
part3 = ''.join(chr(i - 50) for i in [134,115,126,119,133,145,99,105,99,106])
# 'TALES_1718'

oath = part1 + part2 + part3
# 'DEAD_MEN_TELL_NO_TALES_1718'
```

(If the app is emulated or rooted, the token is poisoned and the key is wrong —
this is why the challenge insists on a clean device/emulator bypass.)

## Step 3 — the clean device token

On a genuine, unrooted device the app computes

```
token = 322420958
```

which is `0x1337c0de` — the classic "leet code" constant. The signed/negative
variant `-845496098` (`0xcd9ac0de`) is the tampered/curse path and fails to
decrypt.

## Step 4 — derive the key/IV and decrypt

The vault ciphertext is an array of (signed) byte values:

```
112, -30, -6, -75, -55, 15, 96, 15, 94, -81, -68, 76, 71, 8, -73, -63,
-8, 37, 81, 125, -74, -67, 122, -91, 49, 115, 51, 78, -89, 77, 93, -9,
-49, -126, -86, -21, -80, 110, 46, -51, -33, 23, -94, -105, -89, -48,
60, 69, 26, -26, 108, 13, -11, 56, 47, 52, 42, 117, 126, 74, 87, 118, 51, -104
```

Convert to unsigned (`c % 256`), then:

```python
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

oath  = "DEAD_MEN_TELL_NO_TALES_1718"
token = 322420958
h = format(token & 0xffffffff, "x")            # '1337c0de'

key = hashlib.sha256((oath + ":" + h).encode()).digest()
iv  = hashlib.sha256(("SALT_CARIBBEAN_TIDES_1718:" + h).encode()).digest()[:16]

d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
print(d.update(ct) + d.finalize())
```

Output:

```
FLAG{d34d_m3n_t3ll_n0_t4l35_fr1d4_unl0ck5_th3_cur53d_v4ult}
```

## The honeypot

`strings classes.dex` contains a single plausible-looking flag:

```
FLAG{y0u_f0und_f00ls_g0ld_matey}
```

It is bound to the `btnFoolsGold` / `FOOLS_GOLD_FLAG` UI path and the triage notes
record that the score server rejected it (`INCORRECT FLAG`). The genuine flag is
the one produced by the decryption above. (The other `FLAG{...}` decoys in this
collection belong to *The Phantom Application* — see that writeup.)

## Tools & Methodology

**Tools:** `jadx`, `apktool`, `strings`, `unzip`, Python 3 (`hashlib`,
`cryptography` AES-CBC).

**Method:**

1. Decompiled the APK and reconstructed the `getSeaOath` fragments into
   `DEAD_MEN_TELL_NO_TALES_1718`.
2. Extracted the clean-device token `0x1337c0de` (322420958) and the AES-CBC
   parameters, rejecting the honeypot branch and decoy constants.
3. Reproduced the app's key/IV derivation, decrypted the vault blob, and
   validated the `FLAG{...}` plaintext.

## Flag

```
FLAG{d34d_m3n_t3ll_n0_t4l35_fr1d4_unl0ck5_th3_cur53d_v4ult}
```

## Takeaway

Three layered traps:

1. **String honeypots** — plausible flags in `strings` that the score server
   rejects.
2. **Environment gating** — emulator/root detection flips the device token into a
   poisoned variant, so the same code decrypts to garbage.
3. **Signed-byte parsing** — the ciphertext is stored as Java `byte[]`, so naive
   `bytes([...])` fails on negatives; values must be reduced mod 256.

The crypto itself is standard AES-CBC, but the key material is only correct when
the runtime "sentries" are appeased.
