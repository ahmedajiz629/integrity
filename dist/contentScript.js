"use strict";
/// <reference types="chrome" />
(() => {
    const DEFAULT_ALGORITHM = "sha256";
    const DEFAULT_ENCODING = "base64url";
    const indicator = createIndicator();
    let currentDescriptor = parseIntegrityDescriptor(window.location.hash);
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
        if (!message || typeof message !== "object") {
            return;
        }
        const { type } = message;
        if (type === "PROMPT_TOKEN_GENERATION") {
            if (currentDescriptor) {
                sendResponse({ skipped: true });
                return;
            }
            void handleTokenGenerationRequest();
            sendResponse({ ok: true });
        }
    });
    window.addEventListener("hashchange", () => {
        currentDescriptor = parseIntegrityDescriptor(window.location.hash);
        void bootstrap();
    });
    void bootstrap();
    async function bootstrap() {
        if (!currentDescriptor) {
            updateIndicator("absent", "No integrity token on this URL.");
            await reportTabState("absent");
            return;
        }
        await verifyDescriptor(currentDescriptor);
    }
    async function verifyDescriptor(descriptor) {
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
                await reportTabState("rejected");
                return;
            }
            if (!response.ok) {
                updateIndicator("error", response.error);
                await reportTabState("rejected");
                return;
            }
            if (response.matches) {
                updateIndicator("match", "Integrity verified.");
            }
            else {
                updateIndicator("mismatch", `Digest mismatch. Expected ${descriptor.digest}, received ${response.actualDigest}.`);
                await reportTabState("rejected");
                return;
            }
            await reportTabState("verified");
        }
        catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            updateIndicator("error", message);
            await reportTabState("rejected");
        }
    }
    async function handleTokenGenerationRequest() {
        updateIndicator("pending", "Generating integrity token...");
        await reportTabState("loading");
        try {
            const response = await chrome.runtime.sendMessage({
                type: "GENERATE_PAGE_DIGEST",
                url: window.location.href,
                algorithm: DEFAULT_ALGORITHM,
                encoding: DEFAULT_ENCODING
            });
            if (!response || !response.ok) {
                const errorMessage = response?.error ?? "Unable to generate digest.";
                updateIndicator("error", errorMessage);
                await reportTabState("rejected");
                return;
            }
            applyIntegrityFragment(response.algorithm, response.encoding, response.digest);
            currentDescriptor = parseIntegrityDescriptor(window.location.hash);
            if (currentDescriptor) {
                await verifyDescriptor(currentDescriptor);
            }
        }
        catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            updateIndicator("error", message);
            await reportTabState("rejected");
        }
    }
    async function reportTabState(state) {
        try {
            await chrome.runtime.sendMessage({
                type: "REPORT_TAB_STATE",
                state,
                url: window.location.href
            });
        }
        catch (error) {
            console.warn("Unable to report tab state", error);
        }
    }
    function applyIntegrityFragment(algorithm, encoding, digest) {
        const normalizedAlgorithm = algorithmIdentifierToFragment(algorithm);
        const url = new URL(window.location.href);
        const hashPayload = url.hash.startsWith("#") ? url.hash.slice(1) : url.hash;
        const params = new URLSearchParams(hashPayload);
        params.set("integrity", `${normalizedAlgorithm}-${digest}`);
        const nextHash = params.toString();
        const nextUrl = `${url.origin}${url.pathname}${url.search}${nextHash ? `#${nextHash}` : ""}`;
        if (typeof history.replaceState === "function") {
            history.replaceState(null, document.title, nextUrl);
        }
        else {
            window.location.replace(nextUrl);
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
    function algorithmIdentifierToFragment(identifier) {
        if (typeof identifier === "string") {
            return sanitizeAlgorithmToken(identifier);
        }
        if (typeof identifier === "object" && "name" in identifier && typeof identifier.name === "string") {
            return sanitizeAlgorithmToken(identifier.name);
        }
        return DEFAULT_ALGORITHM;
    }
    function sanitizeAlgorithmToken(value) {
        const clean = value.toLowerCase().replace(/[^a-z0-9]/gu, "");
        if (clean === "sha256" || clean === "sha384" || clean === "sha512") {
            return clean;
        }
        return DEFAULT_ALGORITHM;
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
            error: "#c44536",
            absent: "#6b7280"
        };
        dot.style.backgroundColor = palette[state];
    }
})();
