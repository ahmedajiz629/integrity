/// <reference types="chrome" />

const SUPPORTED_ALGORITHMS: Record<string, AlgorithmIdentifier> = {
  sha256: "SHA-256",
  sha384: "SHA-384",
  sha512: "SHA-512"
};

type VerificationEncoding = "base64" | "base64url";

type VerifyPageMessage = {
  type: "VERIFY_PAGE_DIGEST";
  url: string;
  expectedDigest: string;
  algorithm: string;
  encoding: VerificationEncoding;
};

type VerifyPageResponse =
  | {
      ok: true;
      matches: boolean;
      actualDigest: string;
      algorithm: AlgorithmIdentifier;
      encoding: VerificationEncoding;
      url: string;
    }
  | {
      ok: false;
      error: string;
    };

type GeneratePageDigestMessage = {
  type: "GENERATE_PAGE_DIGEST";
  url: string;
  algorithm: string;
  encoding: VerificationEncoding;
};

type GeneratePageDigestResponse =
  | {
      ok: true;
      digest: string;
      algorithm: AlgorithmIdentifier;
      encoding: VerificationEncoding;
      url: string;
    }
  | {
      ok: false;
      error: string;
    };

type TabVisualState = "absent" | "loading" | "verified" | "rejected";

type ReportTabStateMessage = {
  type: "REPORT_TAB_STATE";
  url: string;
  state: TabVisualState;
};

const TAB_VISUALS: Record<TabVisualState, { color: string; title: string }> = {
  absent: { color: "#6b7280", title: "Web Integrity Guard · Token missing" },
  loading: { color: "#f5a524", title: "Web Integrity Guard · Checking" },
  verified: { color: "#12a454", title: "Web Integrity Guard · Verified" },
  rejected: { color: "#c44536", title: "Web Integrity Guard · Rejected" }
};

type IconDictionary = Record<number, ImageData>;

const tabStates = new Map<number, TabVisualState>();
const iconCache = new Map<TabVisualState, IconDictionary>();

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  if (isVerifyMessage(message)) {
    const tabId = sender.tab?.id;
    if (typeof tabId === "number") {
      void setTabVisualState(tabId, "loading");
    }

    handleVerification(message)
      .then((result) => {
        if (typeof tabId === "number") {
          const nextState: TabVisualState = result.ok && result.matches ? "verified" : "rejected";
          void setTabVisualState(tabId, nextState);
        }
        sendResponse(result);
      })
      .catch((error: unknown) => {
        if (typeof tabId === "number") {
          void setTabVisualState(tabId, "rejected");
        }
        const errorMessage = error instanceof Error ? error.message : String(error);
        sendResponse({ ok: false, error: errorMessage });
      });

    return true;
  }

  if (isGenerateMessage(message)) {
    const tabId = sender.tab?.id;
    if (typeof tabId === "number") {
      void setTabVisualState(tabId, "loading");
    }

    handleDigestGeneration(message)
      .then((result) => {
        if (!result.ok && typeof tabId === "number") {
          void setTabVisualState(tabId, "rejected");
        }
        sendResponse(result);
      })
      .catch((error: unknown) => {
        if (typeof tabId === "number") {
          void setTabVisualState(tabId, "rejected");
        }
        const errorMessage = error instanceof Error ? error.message : String(error);
        sendResponse({ ok: false, error: errorMessage });
      });

    return true;
  }

  if (isReportStateMessage(message)) {
    const tabId = sender.tab?.id;
    if (typeof tabId === "number") {
      void setTabVisualState(tabId, message.state);
    }
    sendResponse({ ok: true });
    return false;
  }

  return false;
});

chrome.action.onClicked.addListener(async (tab) => {
  if (!tab.id || !tab.url) {
    return;
  }

  const state = tabStates.get(tab.id);
  if (state && state !== "absent") {
    return;
  }

  try {
    await chrome.tabs.sendMessage(tab.id, { type: "PROMPT_TOKEN_GENERATION" });
  } catch (error) {
    console.warn("Unable to contact tab for token generation", error);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
});

function isVerifyMessage(message: unknown): message is VerifyPageMessage {
  if (!message || typeof message !== "object") {
    return false;
  }

  const candidate = message as Partial<VerifyPageMessage>;
  return (
    candidate.type === "VERIFY_PAGE_DIGEST" &&
    typeof candidate.url === "string" &&
    typeof candidate.expectedDigest === "string" &&
    typeof candidate.algorithm === "string" &&
    (candidate.encoding === "base64" || candidate.encoding === "base64url")
  );
}

async function handleVerification(message: VerifyPageMessage): Promise<VerifyPageResponse> {
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
      cache: "reload",
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
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return { ok: false, error: errorMessage };
  }
}

function normalizeAlgorithm(input: string): AlgorithmIdentifier | null {
  const key = input.trim().toLowerCase();
  return SUPPORTED_ALGORITHMS[key] ?? null;
}

function normalizeDigest(digest: string, encoding: VerificationEncoding): string | null {
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

function encodeDigest(buffer: ArrayBuffer, encoding: VerificationEncoding): string {
  const base64 = arrayBufferToBase64(buffer);
  if (encoding === "base64") {
    return base64;
  }

  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function timingSafeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let mismatch = 0;
  for (let i = 0; i < a.length; i += 1) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

function stripFragment(inputUrl: string): string {
  try {
    const parsed = new URL(inputUrl);
    parsed.hash = "";
    return parsed.toString();
  } catch (_error) {
    return inputUrl;
  }
}

function isGenerateMessage(message: unknown): message is GeneratePageDigestMessage {
  if (!message || typeof message !== "object") {
    return false;
  }

  const candidate = message as Partial<GeneratePageDigestMessage>;
  return (
    candidate.type === "GENERATE_PAGE_DIGEST" &&
    typeof candidate.url === "string" &&
    typeof candidate.algorithm === "string" &&
    (candidate.encoding === "base64" || candidate.encoding === "base64url")
  );
}

function isReportStateMessage(message: unknown): message is ReportTabStateMessage {
  if (!message || typeof message !== "object") {
    return false;
  }

  const candidate = message as Partial<ReportTabStateMessage>;
  return (
    candidate.type === "REPORT_TAB_STATE" &&
    typeof candidate.url === "string" &&
    (candidate.state === "absent" || candidate.state === "loading" || candidate.state === "verified" || candidate.state === "rejected")
  );
}

async function handleDigestGeneration(
  message: GeneratePageDigestMessage
): Promise<GeneratePageDigestResponse> {
  const normalizedAlgorithm = normalizeAlgorithm(message.algorithm);
  if (!normalizedAlgorithm) {
    return { ok: false, error: `Unsupported algorithm: ${message.algorithm}` };
  }

  const targetUrl = stripFragment(message.url);

  try {
    const response = await fetch(targetUrl, {
      cache: "reload",
      credentials: "include"
    });

    if (!response.ok) {
      return { ok: false, error: `Failed to fetch resource: ${response.status}` };
    }

    const payload = await response.arrayBuffer();
    const digestBuffer = await crypto.subtle.digest(normalizedAlgorithm, payload);
    const digest = encodeDigest(digestBuffer, message.encoding);

    return {
      ok: true,
      digest,
      algorithm: normalizedAlgorithm,
      encoding: message.encoding,
      url: targetUrl
    };
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return { ok: false, error: errorMessage };
  }
}

async function setTabVisualState(tabId: number, state: TabVisualState): Promise<void> {
  tabStates.set(tabId, state);
  const visuals = TAB_VISUALS[state];
  try {
    const imageData = await getIconForState(state);
    await chrome.action.setIcon({ tabId, imageData });
  } catch (error) {
    console.warn("Failed to update icon", error);
  }

  await chrome.action.setTitle({ tabId, title: visuals.title });
}

async function getIconForState(state: TabVisualState): Promise<IconDictionary> {
  const cached = iconCache.get(state);
  if (cached) {
    return cached;
  }

  const assets = createIconAssets(TAB_VISUALS[state].color);
  iconCache.set(state, assets);
  return assets;
}

function createIconAssets(color: string): IconDictionary {
  const sizes = [16, 32];
  const assets: IconDictionary = {} as IconDictionary;

  for (const size of sizes) {
    const canvas = new OffscreenCanvas(size, size);
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      throw new Error("Could not acquire canvas context for icon generation.");
    }

    ctx.clearRect(0, 0, size, size);
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(size / 2, size / 2, size / 2 - 2, 0, Math.PI * 2);
    ctx.fill();
    ctx.strokeStyle = "rgba(0, 0, 0, 0.25)";
    ctx.lineWidth = Math.max(1, size * 0.1);
    ctx.stroke();

    assets[size] = ctx.getImageData(0, 0, size, size);
  }

  return assets;
}
