"use strict";
/// <reference types="chrome" />
const SUPPORTED_ALGORITHMS = {
    sha256: "SHA-256",
    sha384: "SHA-384",
    sha512: "SHA-512"
};
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!isVerifyMessage(message)) {
        return false;
    }
    handleVerification(message)
        .then((result) => sendResponse(result))
        .catch((error) => {
        const errorMessage = error instanceof Error ? error.message : String(error);
        sendResponse({ ok: false, error: errorMessage });
    });
    return true;
});
function isVerifyMessage(message) {
    if (!message || typeof message !== "object") {
        return false;
    }
    const candidate = message;
    return (candidate.type === "VERIFY_PAGE_DIGEST" &&
        typeof candidate.url === "string" &&
        typeof candidate.expectedDigest === "string" &&
        typeof candidate.algorithm === "string" &&
        (candidate.encoding === "base64" || candidate.encoding === "base64url"));
}
async function handleVerification(message) {
    const normalizedAlgorithm = normalizeAlgorithm(message.algorithm);
    if (!normalizedAlgorithm) {
        return { ok: false, error: `Unsupported algorithm: ${message.algorithm}` };
    }
    const normalizedDigest = normalizeDigest(message.expectedDigest, message.encoding);
    if (!normalizedDigest) {
        return { ok: false, error: "Digest is missing or malformed." };
    }
    const targetUrl = stripFragment(message.url);
    try {
        const response = await fetch(targetUrl, {
            cache: "default",
            credentials: "include"
        });
        if (!response.ok) {
            return { ok: false, error: `Failed to fetch resource: ${response.status}` };
        }
        const payload = await response.arrayBuffer();
        const digestBuffer = await crypto.subtle.digest(normalizedAlgorithm, payload);
        const actualDigest = encodeDigest(digestBuffer, message.encoding);
        const matches = timingSafeEquals(actualDigest, normalizedDigest);
        return {
            ok: true,
            matches,
            actualDigest,
            algorithm: normalizedAlgorithm,
            encoding: message.encoding,
            url: targetUrl
        };
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return { ok: false, error: errorMessage };
    }
}
function normalizeAlgorithm(input) {
    const key = input.trim().toLowerCase();
    return SUPPORTED_ALGORITHMS[key] ?? null;
}
function normalizeDigest(digest, encoding) {
    const trimmed = digest.trim();
    if (!trimmed) {
        return null;
    }
    const base64Pattern = /^[A-Za-z0-9+/=]+$/u;
    const base64UrlPattern = /^[A-Za-z0-9-_]+=?=?$/u;
    if (encoding === "base64") {
        return base64Pattern.test(trimmed) ? trimmed : null;
    }
    return base64UrlPattern.test(trimmed) ? trimmed.replace(/=+$/u, "") : null;
}
function encodeDigest(buffer, encoding) {
    const base64 = arrayBufferToBase64(buffer);
    if (encoding === "base64") {
        return base64;
    }
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}
function timingSafeEquals(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    let mismatch = 0;
    for (let i = 0; i < a.length; i += 1) {
        mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return mismatch === 0;
}
function stripFragment(inputUrl) {
    try {
        const parsed = new URL(inputUrl);
        parsed.hash = "";
        return parsed.toString();
    }
    catch (_error) {
        return inputUrl;
    }
}
