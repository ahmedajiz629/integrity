# Web Integrity Guard

Manifest V3 prototype that verifies whether the bytes you expect actually match what the browser fetched. Pages encode their expected digest inside the URL fragment, and the extension re-downloads the resource in a background service worker to check the hash.

## How it works

- The page link must include a fragment parameter named `integrity`, e.g. `https://site.test/#integrity=sha256-BASE64DIGEST`.
- A content script watches for that parameter, shows a floating indicator, and sends the verification request to the background service worker.
- The service worker issues its own `fetch` for the same URL (without the fragment), reuses the HTTP cache when possible, hashes the response body with Web Crypto, and reports the result.
- The indicator turns green on a match, red on mismatch/error, and amber while waiting.

Supported algorithms today: `sha256`, `sha384`, `sha512` with Base64 or Base64url encoded digests.

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
