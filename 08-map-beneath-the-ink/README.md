# Map Beneath the Ink

| | |
|---|---|
| **Challenge ID** | `RwE9om14` |
| **Category** | Forensics |
| **Flag format** | `FLAG{...}` |

## Premise

A collection of photographs, scanned maps, and historical documents was recovered
from a missing pirate captain's quarters. One file hides the real treasure
location "in plain sight", and the challenge asks us to "find what the ink refuses
to reveal".

## Artifacts

```
41cc1a5fd7ff410cb1091b9970266ada.zip
player/evidence/old_map.jpg
player/evidence/ship_photograph.png
player/evidence/historical_document.png
player/evidence/treasure_map.png      1200 x 800 RGB
player/evidence/captain_portrait.jpg
player/evidence/checksums.sha256
```

A README and `challenge_info.txt` frame the task: the map is "incomplete" and the
captain hid something inside one of the images.

## Analysis

Standard stego triage across all five images (`exiftool`, `binwalk`, `strings`,
`zsteg`, `steghide`) shows nothing unusual in metadata or trailing data. The
payload is a plain **spatial LSB** channel, which is easy to miss if you only look
at `zsteg`'s default channel ordering.

`treasure_map.png` is the largest and, being PNG, losslessly preserves LSBs.
Extracting **bit 0 of the blue channel**, scanning rows top-to-bottom and pixels
left-to-right, yields a long ASCII dispatch. The critical detail is the **bit
order**: each byte must be assembled **LSB-first** (`bit[j] << j`), not MSB-first.

```python
from PIL import Image

im = Image.open("treasure_map.png").convert("RGB")
w, h = im.size
px = im.load()

bits = [px[x, y][2] & 1 for y in range(h) for x in range(w)]

out = bytearray()
for i in range(0, len(bits) - 7, 8):
    b = 0
    for j in range(8):
        b |= bits[i + j] << j        # LSB-first
    out.append(b)

print(bytes(out)[1000:1600].decode("latin1"))
```

The payload embeds an ASCII template and a worked example:

```
[VANCE DISPATCH - CABIN VAULT 1718]
...
Target Registry Key: OT-7729-CARIB

THE FINAL VAULT CODE:
Combine the three tokens in the following standard format:
FLAG{<REEF_NAME>_<DEPTH>_<REGISTRY_KEY>}

Example: If Reef=SHELTER_COVE, Depth=10_FATHOMS, Key=SV-1001-ATL
The flag would be: FLAG{SHELTER_COVE_10_FATHOMS_SV-1001-ATL}
```

## Trap: the template is not the flag

The first match in the stream is `FLAG{<REEF_NAME>_<DEPTH>_<REGISTRY_KEY>}`, and
the second is the *example* `FLAG{SHELTER_COVE_10_FATHOMS_SV-1001-ATL}`. Both are
decoy scaffolding — submitting either is wrong.

The real token must be assembled from the actual recovered values earlier in the
same dispatch:

* **Reef name**: `DEAD_MANS_SHALLOWS`
* **Depth**: `14_FATHOMS`
* **Registry key**: `OT-7729-CARIB`

Re-read the dispatch text around offset ~1000 for the true values, then apply the
stated format.

## Tools & Methodology

**Tools:** Python 3 with Pillow/NumPy, `zsteg`, `steghide`, `binwalk`, `exiftool`,
`xxd`.

**Method:**

1. Ran `file`, `exiftool`, `binwalk`, `zsteg -a`, and `steghide` to rule out
   metadata, appended archives, and tool-default LSB payloads.
2. Extracted bit 0 of the blue channel across the PNG, assembled bytes LSB-first,
   and read out the three embedded tokens.
3. Combined the tokens into the `FLAG{...}` value and explicitly rejected the
   map-template decoy `FLAG{SHELTER_COVE_10_FATHOMS_SV-1001-ATL}`.

## Flag

```
FLAG{DEAD_MANS_SHALLOWS_14_FATHOMS_OT-7729-CARIB}
```

## Takeaway

Two independent gotchas:

1. **Bit order inside each byte.** `zsteg`/naive extractors often assume MSB-first;
   this carrier is LSB-first, so the output looks like binary noise until you flip
   it.
2. **Template poisoning.** The extracted text contains both a placeholder template
   and a fully-formed example flag. Never submit the first `FLAG{...}` you see —
   parse the surrounding prose and build the answer from the real tokens.
