# Ghost Ship Unloaded

| | |
|---|---|
| **Challenge ID** | `nmEv7AyW` |
| **Category** | Reverse Engineering |
| **Flag format** | `flag{...}` |

## Premise

Investigators recovered `Remittance_Manifest.jar` from the derelict galleon *Black
Meridian*. It looks like a colonial shipping ledger, but crucial resources are
encrypted inside the JAR, the entry point obscures the keys, and an anomalous
dynamically-loaded module named **QaZagne** guards a sealed treasure vault.

## Artifacts

```
54fcf826a0044653a6b3ea293b6764fe.zip
ghost-ship-unloaded/
  Remittance_Manifest.jar
  captains_log.enc
  ship_manifest.json
  analyst_notes.txt
  execution_trace.log
```

## Step 1 — inspect the JAR

```bash
unzip -l Remittance_Manifest.jar
# com/blackmeridian/crypto/Header.class
# com/blackmeridian/modules/QaZagne.class
# assets/manifest.idx
# assets/payload_alpha.bin
# assets/vault.dat
```

`Header` holds the configuration as an `int[]` named `RAW_CHART`. The ints are
masked with a position-dependent XOR. `javap -p -c` prints the `bipush/sipush`
sequence; a small parser recovers it:

```python
import re
t = open("header.javap").read()
raw = [int(m) for m in re.findall(r"(?:bipush|sipush)\s+(\d+)\s*\n\s*\d+:\s+iastore", t)]
s = "".join(chr((v ^ 90 ^ ((i * 17 + 3) & 0xff)) & 0xff) for i, v in enumerate(raw))
print(s)
```

Decoded `RAW_CHART`:

```
KEY:BlackMeridian171|IV:SargassoSea2026!|SEED:9942
```

So the JAR's resource key is `BlackMeridian171` with IV `SargassoSea2026!`
(AES-128-CBC, PKCS5).

## Step 2 — decrypt the JAR assets

```python
import hashlib, zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"BlackMeridian171"
iv  = b"SargassoSea2026!"
z = zipfile.ZipFile("Remittance_Manifest.jar")

def dec(b):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(b) + d.finalize()
```

`assets/manifest.idx` decrypts to the resource manifest:

```json
{
  "manifest_version": "1718.4-BM",
  "vessel": "Black Meridian",
  "encryption": "AES/CBC/PKCS5Padding",
  "resources": {
    "stage_alpha": {
      "path": "assets/payload_alpha.bin",
      "target_class": "com.blackmeridian.modules.QaZagne",
      "entry_method": "auditVesselCargo",
      "checksum": "8f92a1c0"
    },
    "captains_log": {
      "external_file": "captains_log.enc",
      "salt": "C4PT41N_V4N3_SALT_1718",
      "derivation": "SHA256(MasterKey + Salt)[:16]"
    },
    "treasure_vault": {
      "path": "assets/vault.dat",
      "format": "ENCRYPTED_VAULT_RECORD",
      "required_tokens": ["captain_token", "manifest_seal"],
      "guardian_module": "QaZagne.unlockTreasureVault"
    }
  }
}
```

`assets/payload_alpha.bin` decrypts to the compiled `QaZagne` class
(`auditVesselCargo` / `unlockTreasureVault`).

## Step 3 — recover the captain token

`captains_log.enc` is 1,312 bytes. The manifest says the key is
`SHA256(MasterKey + Salt)[:16]` with salt `C4PT41N_V4N3_SALT_1718`; `MasterKey` is
the chart `KEY` above. The file begins with a **16-byte IV prefix**, then the AES
ciphertext:

```python
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ct = open("captains_log.enc", "rb").read()
iv, body = ct[:16], ct[16:]
k = hashlib.sha256(b"BlackMeridian171" + b"C4PT41N_V4N3_SALT_1718").digest()[:16]

d = Cipher(algorithms.AES(k), modes.CBC(iv)).decryptor()
log = (d.update(body) + d.finalize()).decode()
```

The plaintext is Captain Charles Vane's private log, which contains:

```
[NAV-TOKEN-CAPTAIN-VANE-7701]
...
None shall open the Treasure Vault without the two sacred tokens:
1. The Navigational Pass-Token from this log
2. The Cargo Manifest Seal stamped upon the official shipping register.
```

## Step 4 — the manifest seal

`ship_manifest.json` (and the recovered register) carries the cargo seal:

```
MERIDIAN-SEAL-1718-X99
```

## Step 5 — QaZagne's unlock rite

`QaZagne.unlockTreasureVault` derives its AES key and IV from **both** tokens:

```python
tok  = "NAV-TOKEN-CAPTAIN-VANE-7701"
seal = "MERIDIAN-SEAL-1718-X99"

key = hashlib.sha256((tok + ":" + seal).encode()).digest()[:16]
iv  = hashlib.sha256((seal + ":" + tok).encode()).digest()[:16]

raw = zipfile.ZipFile("Remittance_Manifest.jar").read("assets/vault.dat")
d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
print((d.update(raw) + d.finalize()).decode())
```

Important: decrypt the **raw** `assets/vault.dat` from the archive, *not* the
version already decrypted with `Header`'s chart key — the vault has its own
two-token envelope.

Output (trimmed):

```
================================================================================
BLACK MERIDIAN — CLASSIFIED TREASURE RECOVERY MANIFEST
Vessel: Black Meridian (Sunk 1718, Recovered 2026)
Registry: Port Royal Admiralty Docket #BM-992-SEC
Coordinates: 25°12'N, 71°04'W (Sargasso Sea / Dead Man's Shoal)
================================================================================

Recovered Spoils & Sovereign Cargo:
- 4,500 Royal Spanish Doubloons (Seville Mint, 1712)
- 88 Fine Silver Ingots (Potosi Royal Foundry)
- 12 Ivory Astrolabes & Navigation Spheres
- 1 Cursed Sovereign's Diadem of the Antilles
- Quartermaster Hands' Secret Ledger & Cipher Keys

[+] TREASURE ACCESS GRANTED [+]
THE CURSE OF THE GHOST SHIP IS BROKEN.
THE ARCHIVE HAS SURRENDERED ITS SECRET:

flag{gh0st_sh1p_j4v4_d3c0d3d_q4z4gn3_unm4sk3d_9f4c8a}
================================================================================
```

## Tools & Methodology

**Tools:** `unzip`, `javap -p -c`, `strings`, Python 3 (`zipfile`, `hashlib`,
`cryptography` AES-CBC/GCM).

**Method:**

1. Listed the JAR and disassembled `Header.class` with `javap`; parsed the
   `bipush`/`sipush` sequence and reversed the position-dependent XOR to recover
   `RAW_CHART`.
2. Used `KEY:BlackMeridian171|IV:SargassoSea2026!|SEED:9942` to AES-CBC-decrypt
   the JAR assets, then followed the captain-log and `QaZagne` code paths.
3. Recovered the captain token and manifest seal, then performed the two-token
   vault decryption to obtain the flag.

## Flag

```
flag{gh0st_sh1p_j4v4_d3c0d3d_q4z4gn3_unm4sk3d_9f4c8a}
```

## Takeaway

A clean multi-layer Java RE chain:

1. **Bytecode constant decoding** — `RAW_CHART` is not plaintext; it is an int
   array masked with `v ^ 90 ^ (17i + 3)`.
2. **Resource manifest** — the decrypted `.idx` names every downstream file, salt,
   and derivation.
3. **IV-prefix file format** — `captains_log.enc` stores its IV inline.
4. **Two-token key derivation** — `vault.dat` consumes both the log token and the
   manifest seal, so neither artifact alone is enough.

Each layer leaks exactly the information needed for the next, which is typical of
"unloaded/loaded module" JAR challenges.
