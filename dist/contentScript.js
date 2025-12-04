"use strict";
/// <reference types="chrome" />
(() => {
    const indicator = createIndicator();
    void main();
    async function main() {
        const descriptor = parseIntegrityDescriptor(window.location.hash);
        if (!descriptor) {
            return;
        }
        updateIndicator("pending", `Verifying ${descriptor.label} digest...`);
        try {
            const response = await chrome.runtime.sendMessage({
                type: "VERIFY_PAGE_DIGEST",
                url: window.location.href,
                expectedDigest: descriptor.digest,
                algorithm: descriptor.algorithm,
                encoding: descriptor.encoding
            });
            if (!response) {
                updateIndicator("error", "No response from background script.");
                return;
            }
            if (!response.ok) {
                updateIndicator("error", response.error);
                return;
            }
            if (response.matches) {
                updateIndicator("match", "Integrity verified.");
            }
            else {
                updateIndicator("mismatch", `Digest mismatch. Expected ${descriptor.digest}, received ${response.actualDigest}.`);
            }
        }
        catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            updateIndicator("error", message);
        }
    }
    function parseIntegrityDescriptor(hash) {
        if (!hash || hash.length <= 1) {
            return null;
        }
        const params = new URLSearchParams(hash.slice(1));
        const integrityParam = params.get("integrity");
        if (!integrityParam) {
            return null;
        }
        const [rawAlgorithm, rawDigest] = integrityParam.split("-", 2);
        if (!rawAlgorithm || !rawDigest) {
            return null;
        }
        const normalizedAlgorithm = normalizeAlgorithm(rawAlgorithm);
        if (!normalizedAlgorithm) {
            console.warn("Unsupported integrity algorithm", rawAlgorithm);
            return null;
        }
        const encoding = inferEncoding(rawDigest);
        return {
            algorithm: normalizedAlgorithm,
            encoding,
            digest: rawDigest.trim(),
            label: normalizedAlgorithm.toUpperCase()
        };
    }
    function normalizeAlgorithm(value) {
        const lookup = {
            sha256: "sha256",
            sha384: "sha384",
            sha512: "sha512"
        };
        return lookup[value.trim().toLowerCase()] ?? null;
    }
    function inferEncoding(digest) {
        if (/^[A-Za-z0-9-_]+$/u.test(digest) && digest.includes("-") && !digest.includes("+")) {
            return "base64url";
        }
        return "base64";
    }
    function createIndicator() {
        const root = document.createElement("div");
        root.id = "web-integrity-indicator";
        Object.assign(root.style, {
            position: "fixed",
            bottom: "1rem",
            right: "1rem",
            padding: "0.75rem 1rem",
            borderRadius: "999px",
            fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
            fontSize: "0.9rem",
            color: "#041013",
            background: "rgba(255, 255, 255, 0.95)",
            boxShadow: "0 10px 25px rgba(0, 0, 0, 0.15)",
            border: "1px solid rgba(0, 0, 0, 0.1)",
            zIndex: "2147483647",
            display: "none",
            gap: "0.5rem",
            alignItems: "center"
        });
        const statusDot = document.createElement("span");
        statusDot.id = "web-integrity-indicator-dot";
        Object.assign(statusDot.style, {
            width: "0.5rem",
            height: "0.5rem",
            borderRadius: "999px",
            display: "inline-block"
        });
        const message = document.createElement("span");
        message.id = "web-integrity-indicator-message";
        root.append(statusDot, message);
        document.documentElement.append(root);
        return { root, message };
    }
    function updateIndicator(state, text) {
        const dot = document.getElementById("web-integrity-indicator-dot");
        if (!indicator.root || !indicator.message || !dot) {
            return;
        }
        indicator.root.style.display = "flex";
        indicator.message.textContent = text;
        const palette = {
            pending: "#f5a524",
            match: "#12a454",
            mismatch: "#c44536",
            error: "#c44536"
        };
        dot.style.backgroundColor = palette[state];
    }
})();
