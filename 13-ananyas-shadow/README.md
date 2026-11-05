# Ananya's Shadow

| | |
|---|---|
| **Challenge ID** | `vRyNkY1P` |
| **Category** | OSINT |
| **Flag format** | `Hack!tUp{...}` |
| **Live site** | https://webapp-ten-fawn.vercel.app |

## Premise (Hindi/Hinglish)

> Ananya Varma was investigating a massive security flaw when she suddenly
> disappeared. We think she hid a cache of data on the dark web. We found her old
> blog: trace her digital footprint, find the cache, and extract the secret flag —
> if you have the guts.

So: trace her social profiles → find the encrypted cache → recover the flag.

## Step 1 — the blog and the social graph

The site is a Next.js "Shadow Notes" blog by `av_shadow01`. It links to
`/social/instagram`, `/social/twitter`, `/social/github` and mentions PGP and
AES-256 archives.

The **Instagram** page's bio contains a base64 string:

```
R2l0SHViOiBhdl9zaGFkb3dfZGV2
```

```python
import base64
base64.b64decode("R2l0SHViOiBhdl9zaGFkb3dfZGV2").decode()
# 'GitHub: av_shadow_dev'
```

That yields the GitHub username `av_shadow_dev` and the repo `utils-scripts`
(containing `README.md` and `public_key.asc`).

## Step 2 — the passphrase in image EXIF

The site serves `cafe_photo.jpg`. `exiftool` reveals an ImageDescription that is
not shown in the gallery:

```
$ exiftool cafe_photo.jpg
Image Description : passphrase: Cyber_Shadow_01
```

## Step 3 — the portal key in a deleted Next.js chunk

The blog's HTML references `/_next/static/chunks/110jci9iqs1.2.js`. Fetching that
chunk and searching for the repo name exposes a **commented-out / deleted
commit** block that still ships in the build:

```js
// const PORTAL_KEY = "S3aTtl3_C0ff3e_L0v3r_99";
```

This is the real archive password; `Cyber_Shadow_01` is a decoy for a different
layer.

## Step 4 — find and open `cache.zip`

Directory enumeration on the blog finds a small archive:

```bash
curl -sO https://webapp-ten-fawn.vercel.app/cache.zip
# 477 bytes, WinZip AES (method=AES), made by v6.3
```

It is a WinZip-AES ZIP, so `unzip` fails but `7z` handles it:

```bash
7z x -p'S3aTtl3_C0ff3e_L0v3r_99' cache.zip
```

Two files:

```
read_me.txt -> "Decoy: flag{y0u_m1ss3d_th3_r34l_0n3}"
secrets.txt -> "Congratulations. You've uncovered the truth.
                Flag: Hack!tUp{sh4d0w_n0d3_unv31l3d_99}"
```

## Trap

`flag{y0u_m1ss3d_th3_r34l_0n3}` is an explicit decoy. The genuine flag uses the
`Hack!tUp{...}` format stated by the challenge.

## Tools & Methodology

**Tools:** `curl`, `base64`, `exiftool`, `7z`, `grep`/`strings`, Python 3,
directory enumeration, Instagram/Googlebot fetches.

**Method:**

1. Followed the blog's social links and base64-decoded the Instagram bio to
   `GitHub: av_shadow_dev`, then enumerated the linked repository.
2. Read `cafe_photo.jpg` EXIF (`passphrase: Cyber_Shadow_01`) and grepped the
   shipped Next.js chunks, finding the deleted `PORTAL_KEY` constant.
3. Found `/cache.zip`, extracted the WinZip-AES archive with `7z` using
   `S3aTtl3_C0ff3e_L0v3r_99`, and took the real `Hack!tUp{...}` from
   `secrets.txt` while rejecting the decoy flag.

## Flag

```
Hack!tUp{sh4d0w_n0d3_unv31l3d_99}
```

## Takeaway

A pure OSINT chain where each stage leaks only the next credential:

1. **Base64 in an Instagram bio** → GitHub handle.
2. **EXIF ImageDescription** → a passphrase (and a decoy).
3. **A commented-out constant in a shipped JS chunk** → the real portal key.
4. **Directory enumeration** → `/cache.zip`.

The "deleted" commit was never actually removed from the production bundle —
Next.js shipped the whole chunk, comments included. Grep every JS asset of a
Next.js app for `KEY`, `TOKEN`, `PASSWORD`, and `TODO`.
