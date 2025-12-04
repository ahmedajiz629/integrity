# Web Integrity Guard

Manifest V3 prototype that verifies whether the bytes you expect actually match what the browser fetched. Pages encode their expected digest inside the URL fragment, and the extension re-downloads the resource in a background service worker to check the hash.

## How it works

- The page link should include a fragment parameter named `integrity`, e.g. `https://site.test/#integrity=sha256-BASE64DIGEST`. If it is missing, click the extension icon once to generate one from the current response bytes.
- A content script watches for that parameter (or its absence), shows a floating indicator, and sends verification/generation requests to the background service worker.
- The service worker issues its own `fetch` for the same URL (without the fragment), reuses the HTTP cache when possible, hashes the response body with Web Crypto, and reports the result.
- The browser action icon mirrors the current state: gray (absent), amber (loading/generating), green (verified), and red (rejected/mismatch). The floating indicator uses the same color language.

Supported algorithms today: `sha256`, `sha384`, `sha512` with Base64 or Base64url encoded digests.

## Generating a token on demand

1. Browse to any page that lacks an `integrity` fragment.
2. Click the Web Integrity Guard icon. The icon turns amber while the service worker fetches and hashes the page.
3. Once the digest is ready, the extension injects `#integrity=<algorithm>-<digest>` into the current URL (without a full reload) and immediately verifies it. If everything matches you will see a green icon; otherwise the icon turns red with an explanation in the on-page pill.

Tokens are generated with `sha256` and Base64url encoding by default (no padding, URL-safe characters). Update the code if you need a different policy.

## Getting started

1. **Install dependencies**
   ```bash
   npm install
   ```
2. **Build the TypeScript sources**
   ```bash
   npm run build
   ```
3. **Load the extension in Chrome/Edge**
   - Open `chrome://extensions` (or `edge://extensions`).
   - Enable *Developer mode*.
   - Click *Load unpacked* and pick this folder (the one containing `manifest.json`).

Re-run `npm run build` whenever you change the TypeScript files so that `dist/` stays in sync with `manifest.json`.

## URL format

- Parameter name: `integrity`
- Value: `<algorithm>-<digest>`
  - `algorithm`: `sha256`, `sha384`, or `sha512`
  - `digest`: Base64 (with `+` and `/`) or Base64url (with `-` and `_`). Base64url padding is stripped automatically.

Example:

```
https://example.com/app#integrity=sha256-q5CUc9rwhhHFrufkl+lb7gTLoVQyFIqccIveT6ErIKA=
```

## Scripts

| Command | Purpose |
| --- | --- |
| `npm run build` | Cleans `dist/` and compiles TypeScript. |
| `npm run watch` | Rebuilds on file changes. |
| `npm run lint` | Type-checks without emitting files. |

## Limitations & next steps

- The extension verifies bytes fetched by its own service worker, which might not match what the page initially rendered if the origin serves different variants.
- There is no persistence/UI for recording trusted hashes; everything is derived from the URL fragment today.
- Icons are placeholders—add branded PNGs before publishing.
