# Webhack Solutions

| | |
|---|---|
| **Challenge ID** | `R8y3PA1D` |
| **Category** | OSINT |
| **Flag format** | `HITP{...}` |
| **Link** | https://www.instagram.com/webhackacademy/ |

## Premise

> This challenge is brought to you by Webhack Solutions. Scan the provided QR
> code, decode its contents, and submit the correct value to claim your flag.

The challenge is sponsored OSINT. A QR code is published by Webhack Academy on
Instagram and the academy website. The unlocked hint said:

> *"Some Things are hidden in the reels some on the website. Just Use your skill
> and hunt the flag."*

The hint is literal: the reels lead to the website, but the flag itself is hidden
on the website — not inside the QR payload.

## Step 1 — the reels and the QR

`instagram.com/webhackacademy` is login-walled for normal clients, but Instagram
still serves crawler metadata to link-preview bots. Fetching the reel pages with
`Googlebot` / `facebookexternalhit` user agents exposed the `video_versions`
array, including direct `.mp4` CDN URLs.

Two reels carried the campaign:

| Reel | Length | QR appears | QR payload |
|---|---|---|---|
| `De4Rj_wpIq4` | 48 s | ~44 s | `https://academy.webhacksolutions.com/` |
| `De09-C8pMI-` | 23 s | ~20 s | `https://academy.webhacksolutions.com/` |

Frames were sampled at 10 fps with OpenCV and scanned with `zxingcpp`; both QR
codes decode to the same academy URL. The QR is the entry point, not the flag.

## Step 2 — the coupon code in the comments

The crawler-rendered reel pages also include the comment threads. On reel
`De09-C8pMI-`, user `_.harsh__.raj` commented:

```
HACKITUP15
```

That is the hidden token that connects the Instagram campaign to the academy
site.

## Step 3 — the academy's hidden coupon endpoint

`academy.webhacksolutions.com` is a Next.js app. Its registration page chunk
(`/_next/static/chunks/app/register/page-*.js`) calls:

```js
fetch("/api/coupon/validate", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ code, email, amount })
})
```

`robots.txt` also disallows `/api/`, `/dev/`, `/confirmation/`,
`/registration-success`, and `/payment-status` — a strong hint that the coupon
API is the interesting surface. `/dev/` itself returns 404.

## Step 4 — validate `HACKITUP15`

```bash
curl -s https://academy.webhacksolutions.com/api/coupon/validate \
  -H 'Content-Type: application/json' \
  --data '{"code":"HACKITUP15","email":"test@example.com","amount":4999}'
```

Response:

```json
{
  "success": true,
  "valid": true,
  "code": "HACKITUP15",
  "type": "PERCENTAGE",
  "discountAmount": 750,
  "originalAmount": 4999,
  "finalAmount": 4249,
  "message": "Special 15% discount HITP{hackitup_X_webhackacademy}"
}
```

The coupon description field leaks the flag. For comparison, the public
`CYBERNITIN10` code returns a generic `"Special 10% discount"` message; only the
hidden `HACKITUP15` code carries the `HITP{...}` string.

## Evidence

| File | Contents |
|---|---|
| `evidence/reel_De4Rj_wpIq4.mp4` | 48-second campaign reel |
| `evidence/reel_De09-C8pMI-.mp4` | 23-second reel that ends on the QR |
| `evidence/qr_frame_reel1.png` | frame at ~45 s with the QR |
| `evidence/qr_frame_reel2.png` | frame at ~20 s with the QR |
| `evidence/instagram_reel2_crawler.html` | crawler view containing the `HACKITUP15` comment and video metadata |
| `evidence/coupon_validate_HACKITUP15.json` | raw API response containing the flag |

## Tools & Methodology

**Tools:** `curl` with crawler user agents (`Googlebot`,
`facebookexternalhit`), Python 3 (`re`, `json`, `urllib`), OpenCV (`cv2`) for
frame sampling, `zxingcpp` for QR decoding, `jq`/Python for JSON, and the
academy's Next.js chunks for endpoint discovery.

**Method:**

1. Fetched the Instagram reels as a link-preview crawler, extracted
   `video_versions[].url`, and downloaded both MP4s with a normal desktop UA and
   an Instagram referer.
2. Sampled frames at 10 fps with OpenCV and decoded each frame with `zxingcpp`;
   the QR resolves to `https://academy.webhacksolutions.com/`.
3. Read the crawler-rendered comment thread and found the coupon code
   `HACKITUP15` on the second reel.
4. Crawled the academy site, inspected `robots.txt` and the registration JS chunk,
   and identified `POST /api/coupon/validate`.
5. Submitted `HACKITUP15` and read the flag out of the returned coupon
   `message`/`description` field.

## Flag

```
HITP{hackitup_X_webhackacademy}
```

## Takeaway

The QR alone was only the entry point. The real chain was *reel → comment →
coupon API*, and the API leaked the flag in a user-visible discount message.
Crawler user agents are often enough to recover Instagram post metadata after the
normal web UI is locked down; save the comment/coupon response at solve time.
