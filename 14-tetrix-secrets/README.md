# Tetrix Secrets

| | |
|---|---|
| **Challenge ID** | `5jEznwEr` |
| **Category** | Reverse Engineering |
| **Flag format** | `Hack!tUp{...}` |

## Premise

A developer built a Tetris-style game called **Tetrix**. While testing in debug
mode they "left behind something they shouldn't have". The game plays normally,
but a secret is hidden inside the game binary — "not behind gameplay, not locked
behind a high score ... somewhere much simpler. Sometimes the biggest secrets
aren't hidden deep — they're just waiting to be read."

## Artifact

The attachment is a **89 MB Google Drive download** — `HackItUp.exe`, a Windows
PE32+ executable. (The Drive link presents a virus-scan warning page first; the
real file must be fetched through
`drive.usercontent.google.com/download?id=...&export=download&confirm=t`.)

```
HackItUp.exe   93,021,777 bytes
```

## Analysis

`file` identifies a PE32+ GUI executable. Strings show a **Godot 4.3** engine
(`GDPC`, `res://`, `default_env.tres`, `godot` version markers), so this is a
Godot game with an **embedded PCK** appended to the PE.

### Locate the embedded pack

Godot PCK header (`GDPC`, little-endian):

```python
import struct
data = open("HackItUp.exe", "rb").read()

pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
opt  = struct.unpack_from("<H", data, pe + 20)[0]
base = pe + 24 + opt
for i in range(nsec):
    o = base + i * 40
    name = data[o:o+8].rstrip(b"\x00")
    vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
    print(name, hex(roff), hex(rsize))
```

One section is literally named `pck`:

```
b'pck'  raw offset 0x5036600  raw size 0x880020  (8,913,952 bytes)
```

At `0x5036600` the magic is `GDPC`, then `pack_version = 2`, Godot `4.3.0`.

### The flag is at the very end of the pack

The pack's index lists the imported assets (`res://.godot/imported/...`), but at
the **physical end of the executable** there is a second, fake `GDPC` marker
followed by ASCII — the debug leftover:

```python
data = open("HackItUp.exe", "rb").read()
i = data.rfind(b"Hack!tUp{")
print(i, data[i:data.find(b"}", i) + 1])
```

Tail of the file:

```
... res://default_env.tres
    \x14\x00\x88\x00\x00\x00\x00\x00
    G D P C
    Hack!tUp{A9xK2LmP0QrT7vW4YzB8cD1eF6gH3J5N0U2X9s}\n
```

`strings -a HackItUp.exe | grep 'Hack!tUp{'` finds it immediately; the `rfind`
above confirms it is at offset `93021728`, 49 bytes from EOF.

## Tools & Methodology

**Tools:** `file`, `strings`, `binwalk`, `xxd`/`hexdump`, Python 3 (`struct`,
`rfind`), a PE section-table parser.

**Method:**

1. Identified the Godot 4.3 PE and parsed its section table to find the embedded
   `pck` section at `0x5036600` (`GDPC`, pack version 2).
2. Walked the PCK index to map the imported assets, then scanned the physical end
   of the executable where a second, fake `GDPC` marker precedes ASCII data.
3. Confirmed the `Hack!tUp{...}` string at offset 93021728 and validated it
   against the challenge flag format.

## Flag

```
Hack!tUp{A9xK2LmP0QrT7vW4YzB8cD1eF6gH3J5N0U2X9s}
```

## Takeaway

Engine-packed games (Godot `GDPC`, Unity `globalgamemanagers`, Unreal `.pak`)
append their asset pack to the executable. A quick `binwalk`/section-table pass
finds it, and `strings` often finds debug leftovers without any unpacking at all.
The challenge's hint — "just waiting to be read" — was literal: the flag is plain
ASCII at the end of the file, after a deliberately planted `GDPC` marker.
