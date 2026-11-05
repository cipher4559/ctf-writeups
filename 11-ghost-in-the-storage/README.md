# Ghost in the Storage

| | |
|---|---|
| **Challenge ID** | `vRyNeNEP` |
| **Category** | Mobile Security |
| **Flag format** | `FLAG{...}` |

## Premise

A seized Pixel 6a belonging to quartermaster "The Keeper" was wiped right before
capture. His parting line: *"Some things disappear from the screen, but never from
the storage."* We must carve deleted SQLite records, parse the Android backup,
inspect image caches, and correlate navigation telemetry to rebuild the secret
dispatch.

## Artifacts

```
22ea1c2c8a3846fc8205bcff433f8e02.zip
ghost-in-the-storage-player/evidence/
  android_backup/backup.ab            Android backup (zlib + tar)
  databases/keeper_vault.db           SQLite, with free-page slack
  databases/nav_cache.db              navigation telemetry
  shared_prefs/crypto_state.xml       KDF salt + recipe
  shared_prefs/org.blackflag.keeper_preferences.xml
  shared_prefs/session_cache.xml
  logs/logcat.txt                     app debug log
  logs/dmesg.txt
  evidence_manifest.txt               SHA-256 of every artifact
```

## Step 1 — read the crypto recipe

The live `shared_prefs/crypto_state.xml` shows the salt was destroyed by the wipe:

```xml
<string name="kdf_algorithm">PBKDF2WithHmacSHA256</string>
<int name="kdf_iterations" value="100000" />
<int name="key_length_bits" value="256" />
<string name="master_salt_hex">PURGED_ON_WIPE_ALERT</string>
<string name="wipe_audit_note">
  Master salt cleared by user emergency command.
  Historical copy preserved in prior adb backup snapshot.
</string>
```

The audit note is the pointer: the **prior `backup.ab` snapshot** still holds the
real salt. Decompress it and read
`apps/org.blackflag.keeper/sp/crypto_state.xml`:

```xml
<string name="master_salt_hex">50697261746553616c74323032345661756c7421</string>
<string name="master_salt_ascii">PirateSalt2024Vault!</string>
<string name="key_derivation_recipe">
  PBKDF2(passphrase=Chart_Passphrase:Waypoint_Sector_Token,
         salt=master_salt_hex, iter=100000, 256bit)
</string>
```

So the AES key is

```
key = PBKDF2-HMAC-SHA256(password = "<Chart_Passphrase>:<Sector_Token>",
                         salt = "PirateSalt2024Vault!",
                         iterations = 100000, dkLen = 32)
```

Three unknowns: the chart passphrase, the sector token, and the ciphertext+IV.

## Step 2 — parse the Android backup

`backup.ab` is an unencrypted `ANDROID BACKUP` file
(`ANDROID BACKUP\n5\n1\nnone\n` + zlib). Skip the 24-byte header, inflate, and
untar:

```python
import zlib, tarfile, io

d = open("android_backup/backup.ab", "rb").read()
off = 24                      # len("ANDROID BACKUP\n5\n1\nnone\n")
body = zlib.decompress(d[off:])
tf = tarfile.open(fileobj=io.BytesIO(body))
for m in tf.getmembers():
    print(m.name, m.size)
```

It contains only four app files:

```
apps/org.blackflag.keeper/_manifest
apps/org.blackflag.keeper/sp/crypto_state.xml        <- the preserved salt
apps/org.blackflag.keeper/sp/org.blackflag.keeper_preferences.xml
apps/org.blackflag.keeper/f/backup_manifest.json
```

This is the "prior adb backup snapshot" the wiped device's audit note referred to.

`logcat.txt` shows the cache fetch and the recipe:

```
DiskLruCache: Entry ... verified. URL: https://cdn.corsair-relay.net/charts/san_salvador_reef.png
CorsairCrypto: Recipe format: PBKDF2(passphrase = <Chart_Passphrase> + ":" +
               <Waypoint_77_Sector_Token>, salt = <crypto_state.xml:master_salt_hex>,
               iterations = 100000)
```

So the passphrase lives **inside the cached chart image**, not in a config file.

## Step 3 — recover the deleted transmission from page slack

`keeper_vault.db` has a `transmissions` table. Live rows are daily noise; the
interesting row (`id = 4`) is deleted. With `sqlite3` the row is gone, but the
bytes remain in unused page space:

```python
d = open("keeper_vault.db", "rb").read()
i = d.find(b"ad0125ed")                 # start of the hex payload
j = d.find(b"CONFIDENTIAL_PURGED")      # end of the deleted record
rec = d[i:j]
payload = bytes.fromhex(rec[:-32].decode())
iv      = bytes.fromhex(rec[-32:].decode())
```

The record layout is just concatenated TEXT columns — `payload_hex` followed by a
32-hex-character `iv_hex`, then the `status` value. A partial `strings` view shows:

```
@Capt_Flint | The Keeper | COURIER_DISPATCH_MASTER_VAULT_TOKEN |
ad0125ed...849123 | <32 hex IV> | CONFIDENTIAL_PURGED
```

## Step 4 — get the chart passphrase from the image-cache metadata

The DiskLruCache stores each entry as `<hash>.0` (the body: a 800×600 PNG,
`san_salvador_reef.png`) and `<hash>.1` (the HTTP response metadata). The
passphrase is **not** in the pixels — it is in the HTTP headers recorded in
`7c94b79b9a6744319ff422f28328c6e7.1`:

```
https://cdn.corsair-relay.net/charts/san_salvador_reef.png
GET
HTTP/1.1 200 OK
Content-Type: image/png
Content-Length: 26747
X-Sector-Target: WP-77
X-Chart-Title: San Salvador Deep Reef
X-Cipher-Passphrase: DeadMenTellNoTales
```

The **sector token** comes from `nav_cache.db` → `waypoints.sector_token`:

```
SAN_SALVADOR_REEF_1729
```

(`shared_prefs/..._preferences.xml` only has the short `default_sector` value
`SAN_SALVADOR_REEF`; the full token includes the `_1729` suffix.)

## Step 5 — decrypt

```python
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

salt   = b"PirateSalt2024Vault!"
sector = "SAN_SALVADOR_REEF_1729"
pw     = ("DeadMenTellNoTales:" + sector).encode()

key = hashlib.pbkdf2_hmac("sha256", pw, salt, 100000, 32)
dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
print((dec.update(payload) + dec.finalize()).decode())
```

Plaintext:

```json
{"vault_id": "VAULT_BLACK_BEARD_ARCHIVE",
 "sector": "SAN_SALVADOR_REEF",
 "timestamp": 1729864200000,
 "transmission_type": "MASTER_SECRET_DISPATCH",
 "clearance": "THE_KEEPER_EYES_ONLY",
 "flag": "FLAG{d34d_m3n_t3ll_n0_t4l3s_but_fr33l1sts_d0_7a9f}"}
```

## Tools & Methodology

**Tools:** Python 3 (`zlib`, `tarfile`, `hashlib`), `sqlite3`, `strings`, `xxd`,
`cryptography` AES-CBC, `binwalk`/`foremost` for carving checks.

**Method:**

1. Read `crypto_state.xml` and the wipe audit note, then parsed `backup.ab`
   (24-byte header + zlib + tar) to recover the preserved PBKDF2 salt.
2. Carved the deleted `transmissions` row (`id=4`) from SQLite free-page slack by
   locating the hex payload, IV, and status markers in the raw DB bytes.
3. Pulled `X-Cipher-Passphrase` from the DiskLruCache `.1` metadata and the
   sector token from `nav_cache.db`.
4. Derived the key with PBKDF2-HMAC-SHA256 (100,000 iterations) and
   AES-CBC-decrypted the carved payload.

## Flag

```
FLAG{d34d_m3n_t3ll_n0_t4l3s_but_fr33l1sts_d0_7a9f}
```

## Takeaway

The flag requires **three different forensic sources** to line up:

* **SQLite free-page slack** — a deleted row still lives in unused page bytes;
  never trust a logical `SELECT` for recovery.
* **Android backup parsing** — `backup.ab` is zlib + tar, trivially unpacked when
  not encrypted.
* **Image-cache OSINT** — the passphrase ships inside a cached PNG fetched from a
  CDN URL recorded in `logcat`, so the URL itself is a lead.

A "secure" PBKDF2 envelope is worthless if the passphrase and sector token both sit
in plaintext on the device.
