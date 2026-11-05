# The Phantom Application

| | |
|---|---|
| **Challenge ID** | `v7yPz0g4` |
| **Category** | Mobile Security |
| **Flag format** | `FLAG{...}` |

## Premise

An Android device belonging to a missing navigator of the Phantom Fleet carries
`Phantom Navigator` (`com.phantom.navigator`). It looks like a nautical utility,
but stores an encrypted ledger inside an authenticated "Treasure Vault". We must
reverse the APK, defeat the passcode check, extract the ledger, and decrypt it.

## Artifacts

```
88e316f857714a10856ac9ef11c5df7f.zip
player/evidence/phantom_navigator.apk
```

Decompile with `jadx`:

```bash
jadx -d jadx-phantom phantom_navigator.apk
```

Key classes: `SecretVaultActivity`, `StorageManager`, `QuartermasterValidator`,
`SecurityBridge`.

## Step 1 — the passcode check

`QuartermasterValidator.validatePasscode` does two things:

```java
private static final int XOR_KEY = 42;
private static final int[] TRANSFORM_TABLE = {
    121, 65, 95, 70, 27, 12, 105, 88, 26, 89, 89,
    104, 26, 68, 25, 89, 117, 27, 29, 27, 18, 11
};

public static boolean validatePasscode(String str) {
    if (str == null || str.length() != TRANSFORM_TABLE.length) return false;
    byte[] b = str.getBytes(StandardCharsets.UTF_8);
    for (int i = 0; i < TRANSFORM_TABLE.length; i++) {
        if ((b[i] ^ XOR_KEY) != TRANSFORM_TABLE[i]) return false;
    }
    return EXPECTED_PASSCODE_HASH.equalsIgnoreCase(computeSha256(str));
}
```

The table is just the UTF-8 passcode XOR 42, so the passcode falls out directly:

```python
TABLE = [121,65,95,70,27,12,105,88,26,89,89,104,26,68,25,89,117,27,29,27,18,11]
passcode = ''.join(chr(i ^ 42) for i in TABLE)
# 'Skul1&Cr0ssB0n3s_1718!'
```

Its SHA-256 is `58a8765b28b306902bdb027f58ab4f67f736648b9c96cd889409fa07af2ead7f`,
which matches `EXPECTED_PASSCODE_HASH` — the passcode is confirmed, not guessed.

## Step 2 — the ledger key

`StorageManager` contains the encrypted `DEFAULT_LEDGER` and builds the AES key as:

```java
key = SHA256(passcode + ":" + nonce + ":PHANTOM_FLEET_KEY")
iv  = "CaribbeanSea1718"      // 16 ASCII bytes
```

with `nonce = "D4RK_T1D3S_7721"`. The nonce and IV are string constants visible in
the decompiled classes / `strings output`.

## Step 3 — decrypt the ledger

`DEFAULT_LEDGER` hex from the app:

```
342a385b65e74cc4f19549f1a778ef878610294ca053ee65afee69c55ba67890
0242d2d248a2dfa2166d8e688666513176b90abc25c0cb4245f9640647f6eeb1
```

```python
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

passcode = "Skul1&Cr0ssB0n3s_1718!"
nonce    = "D4RK_T1D3S_7721"
key = hashlib.sha256((passcode + ":" + nonce + ":PHANTOM_FLEET_KEY").encode()).digest()

ct = bytes.fromhex("342a385b65e74cc4f19549f1a778ef878610294ca053ee65afee69c55ba67890"
                   "0242d2d248a2dfa2166d8e688666513176b90abc25c0cb4245f9640647f6eeb1")
iv = b"CaribbeanSea1718"

d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
print(d.update(ct) + d.finalize())
```

Output (trailing bytes are filler):

```
FLAG{ph4nt0m_n4v1g4t0r_cr4ck3d_th3_bl4ck_sp0t_7721}\r\r\r...
```

## Decoys

The APK is salted with plausible-looking flags that the score server rejects:

```
classes.dex:      FLAG{sh4r3d_pr3fs_c4n_l13_t0_y0u}
classes.dex:      FLAG{h4rdc0d3d_j4v4_c0nst4nts_4r3_f4k3}
resources.arsc:   FLAG{r3s0urc3_3xtr4ct10n_1s_n0t_th3_tr34sur3}
resources.arsc:   FLAG{str1ngs_xm1_1s_t00_34sy_pir4t3}
```

None of these are the answer; the real flag only appears after the ledger
decryption above. (The Cursed APK has its own separate `FOOLS_GOLD` decoy.)

## Tools & Methodology

**Tools:** `jadx` (DEX decompilation), `apktool`, `strings`, Python 3
(`hashlib`, `cryptography` AES-CBC).

**Method:**

1. Decompiled `classes.dex` with jadx and read `QuartermasterValidator`:
   `passcode[i] ^ 42 == TRANSFORM_TABLE[i]` plus a SHA-256 equality check.
2. Reversed the XOR table to obtain `Skul1&Cr0ssB0n3s_1718!` and verified its
   SHA-256 against `EXPECTED_PASSCODE_HASH`.
3. Rebuilt the AES key `SHA256(passcode:nonce:PHANTOM_FLEET_KEY)` with nonce
   `D4RK_T1D3S_7721`, used IV `CaribbeanSea1718`, and decrypted the ledger,
   discarding the embedded decoy flags.

## Flag

```
FLAG{ph4nt0m_n4v1g4t0r_cr4ck3d_th3_bl4ck_sp0t_7721}
```

## Takeaway

The obfuscation is only skin deep: `TRANSFORM_TABLE` is a plain XOR-42 blob, and
the "authenticated vault" derives its AES key from material that ships inside the
APK. Client-side secrets are always recoverable — the passcode must be verified
server-side or used to unlock a key that never leaves a secure element. The
trailing `\r` bytes also show the decryptor does not validate padding, so the
result must be scanned for the flag rather than unpadded strictly.
