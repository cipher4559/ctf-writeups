# THE CAPTAIN'S LAST LOG

| | |
|---|---|
| **Challenge ID** | `2jyopv1a` |
| **Category** | Forensics |
| **Flag format** | `FLAG{...}` |

## Premise

An abandoned pirate ship, a missing captain, and a recovered storage device. We must
recover Captain Vance's **deleted final log** and uncover his last secret.

## Artifact

```
67626ea3d2f145349f67c4f37ea45919.zip
player/evidence/captain_disk.E01      258,679 bytes
player/evidence/checksums.sha256
```

`captain_disk.E01` is an **EnCase 6 / Expert Witness Format** image: 64 MiB, deflate
compressed, single segment. `ewfinfo` identifies it cleanly, but the packaged
`ewfexport` is unusable non-interactively (it prompts for segment size and writes
0 bytes), so the raw stream had to be decoded by hand.

## Step 1 — decode E01 to a raw disk

The E01 stores its data in 32 KiB compressed chunks described by a **section
table**. The relevant structures are:

```
header2  -> section descriptors (type, next offset, size)
sectors  -> chunk data (zlib per chunk)
table    -> chunk offsets
```

A small Python decoder walks the section chain, reads the `sectors` section, and
zlib-inflates each chunk to build `disk.raw`. The result is a 64 MiB NTFS volume
whose boot sector reports **sectors-per-cluster = 8 (4 KiB clusters)** and
**MFT cluster = 4**, so the NTFS partition begins at **sector 2048** (the standard
1 MiB alignment).

## Step 2 — list and carve deleted files

Using Sleuth Kit against the raw image:

```bash
mmls disk.raw                     # partition starts at sector 2048
fls -o 2048 -r disk.raw           # recursive listing, incl. deleted
```

The listing shows the expected `Captains_Quarters/journal_entries/` tree, plus two
entries marked deleted (`-/r *`):

```
88-128-2:  Captains_Quarters/journal_entries/journal_1723_11_24_final.txt
87-128-2:  Maintenance_and_Stores/scrapped_inventory_draft.txt
```

Inode **88** is the final log. It is still fully resident in the MFT (2,219 bytes),
so it can be recovered directly:

```bash
icat -o 2048 disk.raw 88 > inode_88.bin
```

## Step 3 — read the log and derive the Vigenère key

The recovered entry is Captain Silas Vance's last testament. It states the
confession is sealed with a **Vigenère cipher (letters shifted, case and
punctuation preserved)**, keyed by:

```
KEY = <NIGHT_WATCHWORD><VOLUME_LABEL>
```

* The **night watchword** is in `Navigation_and_Logs/ship_logs_autumn_1723.txt`
  on the eve of the mutiny, 23 November 1723 → **`LEVIATHAN`**.
* The **volume label** is filesystem metadata:

```bash
ntfslabel disk.raw            # or fsstat -o 2048 disk.raw | grep -i label
# -> BLACK_TIDE
```

So the key is `LEVIATHANBLACK_TIDE` (19 characters, 18 letters). Note the label
itself contains an underscore, which is preserved as a non-letter and skipped
while shifting.

## Step 4 — decrypt

```python
def vigenere_decrypt(text, key):
    # strip the underscore: only letters shift the alphabet
    k = [c for c in key.upper() if c.isalpha()]
    out, ki = [], 0
    for ch in text:
        if ch.isalpha():
            shift = ord(k[ki % len(k)]) - 65
            base = 65 if ch.isupper() else 97
            out.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)

ct = ("Elz brxhshsp oh dam Veyxv Msilrnoka kc gww pzwo bo moe qfpp.\n"
      "K lnzlio xcm ikvn pipsv yg Lheo Qvvs Vhy, gxplxo iifid rjzta vf gip wgoiqqk aegu,\n"
      "mtykre mepotbk xsi oeig joebw bqeelhvd eo kohydvoltgc 18 21 44 G, 64 31 18 E.\n"
      "Wlp wvkrxk cboqeucbwq sq Wdtal Caadp: "
      "FNKZ{d4qg3_d1p4n_l34d_f4us_p4z_d3ct3d_1723}")

print(vigenere_decrypt(ct, "LEVIATHANBLACK_TIDE"))
```

Plaintext:

```
The treasure of the Santa Esperanza is not lost to the deep.
I buried the iron chest on Dead Mans Cay, twelve paces north of the weeping palm,
marked beneath the twin coral boulders at coordinates 18 21 44 N, 64 31 18 W.
The sacred confession of Silas Vance: FLAG{v4nc3_s1l4s_d34d_m4ns_c4y_s3cr3t_1723}
```

`FNKZ` decrypts to `FLAG`, and the whole ciphertext resolves to the flag. Note the
key is filtered to letters only (`LEVIATHANBLACKTIDE`, 18 chars); counting the
underscore in `BLACK_TIDE` shifts every subsequent letter and produces garbage.

## Tools & Methodology

**Tools:** Python 3 (`struct`, `zlib`) for the E01 section decoder, The Sleuth
Kit (`mmls`, `fls`, `icat`), `ewfexport`/`pyewf` as a cross-check, a Vigenère
solver.

**Method:**

1. Walked the E01 section table and zlib-inflated its 32 KiB chunks to rebuild
   `disk.raw` (64 MiB NTFS).
2. Found the NTFS partition at sector 2048 with `mmls`, listed deleted entries
   with `fls -o 2048 -r`, and carved the resident final log from inode 88 with
   `icat -o 2048`.
3. Read the recovered log, derived the Vigenère key from the watchword
   `LEVIATHAN` plus the volume label `BLACK_TIDE`, and decrypted the ciphertext.

## Flag

```
FLAG{v4nc3_s1l4s_d34d_m4ns_c4y_s3cr3t_1723}
```

## Takeaway

Deleted files on NTFS usually survive in the MFT until the record is reused —
`fls -r` + `icat` is often all you need. The Vigenère key deliberately combines a
**content** secret (the watchword in a log file) with **filesystem metadata** (the
volume label), which is why a pure file-content carve is not sufficient. Always
run `fsstat`/`ntfslabel`, too.
