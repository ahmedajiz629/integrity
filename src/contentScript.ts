/// <reference types="chrome" />

(() => {
  type ContentVerificationEncoding = "base64" | "base64url";
  type TabVisualState = "absent" | "loading" | "verified" | "rejected";

  type SourceDescriptor = {
    provider: "github";
    repo: string;
    runId: string;
    jobId: string;
    logUrl: string;
    portalUrl: string;
  };

  type IntegrityDescriptor = {
    algorithm: string;
    encoding: ContentVerificationEncoding;
    digest: string;
    label: string;
    source: SourceDescriptor | null;
  };

  type ContentVerifyPageMessage = {
    type: "VERIFY_PAGE_DIGEST";
    url: string;
    expectedDigest: string;
    algorithm: string;
    encoding: ContentVerificationEncoding;
  };

  type ContentVerifyPageResponse =
    | {
        ok: true;
        matches: boolean;
        actualDigest: string;
        algorithm: AlgorithmIdentifier;
        encoding: ContentVerificationEncoding;
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
    encoding: ContentVerificationEncoding;
  };

  type GeneratePageDigestResponse =
    | {
        ok: true;
        digest: string;
        algorithm: AlgorithmIdentifier;
        encoding: ContentVerificationEncoding;
        url: string;
      }
    | {
        ok: false;
        error: string;
      };

  type VerifySourceMessage = {
    type: "VERIFY_SOURCE_REFERENCE";
    token: string;
    source: SourceDescriptor;
  };

  type VerifySourceResponse =
    | {
        ok: true;
        found: boolean;
        provider: "github";
        logUrl: string;
        portalUrl: string;
      }
    | {
        ok: false;
        error: string;
        authRequired?: boolean;
        loginUrl?: string;
      };

  type ReportSourceSummaryMessage = {
    type: "REPORT_SOURCE_SUMMARY";
    hasSource: boolean;
    portalUrl?: string;
  };

  const DEFAULT_ALGORITHM = "sha256";
  const DEFAULT_ENCODING: ContentVerificationEncoding = "base64url";

  const indicator = createIndicator();
  const dangerOverlay = createDangerOverlay();
  let currentDescriptor: IntegrityDescriptor | null = parseIntegrityDescriptor(window.location.hash);
  let currentSource: SourceDescriptor | null = currentDescriptor?.source ?? null;

  chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
    if (!message || typeof message !== "object") {
      return;
    }

    const { type } = message as { type?: string };
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
    currentSource = currentDescriptor?.source ?? null;
    void bootstrap();
  });

  void bootstrap();

  async function bootstrap() {
    currentSource = currentDescriptor?.source ?? null;
    updateSourceBadge(currentSource);
    await reportSourceSummary(Boolean(currentSource), currentSource?.portalUrl);

    if (!currentDescriptor) {
      updateIndicator("absent", "No integrity token on this URL.");
      await reportTabState("absent");
      return;
    }

    await verifyDescriptor(currentDescriptor);
  }

  async function verifyDescriptor(descriptor: IntegrityDescriptor) {
    updateIndicator("pending", `Verifying ${descriptor.label} digest...`);

    try {
      const response = await chrome.runtime.sendMessage<
        ContentVerifyPageMessage,
        ContentVerifyPageResponse
      >({
        type: "VERIFY_PAGE_DIGEST",
        url: window.location.href,
        expectedDigest: descriptor.digest,
        algorithm: descriptor.algorithm,
        encoding: descriptor.encoding
      });

      if (!response) {
        await escalateDanger("error", "Verification unavailable", "No response from background script.");
        return;
      }

      if (!response.ok) {
        await escalateDanger("error", "Verification failed", response.error);
        return;
      }

      if (!response.matches) {
        await escalateDanger(
          "mismatch",
          "Digest mismatch detected",
          `Expected ${descriptor.digest}, received ${response.actualDigest}.`
        );
        return;
      }

      if (descriptor.source) {
        const sourceStatus = await verifySourceReference(descriptor);
        if (sourceStatus === "success") {
          updateIndicator("match", "Integrity & provenance verified.");
          await reportTabState("verified");
        } else if (sourceStatus === "auth") {
          await reportTabState("loading");
        }
        return;
      }

      updateIndicator("match", "Integrity verified.");
      await reportTabState("verified");
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      await escalateDanger("error", "Verification error", message);
    }
  }

  async function handleTokenGenerationRequest() {
    updateIndicator("pending", "Generating integrity token...");
    await reportTabState("loading");

    try {
      const response = await chrome.runtime.sendMessage<
        GeneratePageDigestMessage,
        GeneratePageDigestResponse
      >({
        type: "GENERATE_PAGE_DIGEST",
        url: window.location.href,
        algorithm: DEFAULT_ALGORITHM,
        encoding: DEFAULT_ENCODING
      });

      if (!response || !response.ok) {
        const errorMessage = response?.error ?? "Unable to generate digest.";
        await escalateDanger("error", "Token generation failed", errorMessage);
        return;
      }

      applyIntegrityFragment(response.algorithm, response.encoding, response.digest);
      currentDescriptor = parseIntegrityDescriptor(window.location.hash);
      currentSource = currentDescriptor?.source ?? null;
      await bootstrap();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      await escalateDanger("error", "Token generation error", message);
    }
  }

  type SourceVerificationStatus = "success" | "auth" | "failure";

  async function verifySourceReference(descriptor: IntegrityDescriptor): Promise<SourceVerificationStatus> {
    if (!descriptor.source) {
      return "success";
    }

    updateIndicator("pending", "Checking provenance log...");

    try {
      const response = await chrome.runtime.sendMessage<VerifySourceMessage, VerifySourceResponse>({
        type: "VERIFY_SOURCE_REFERENCE",
        token: descriptor.digest,
        source: descriptor.source
      });

      if (!response) {
        await escalateDanger("error", "Provenance unavailable", "No response from background script.");
        return "failure";
      }

      if (!response.ok) {
        if (response.authRequired) {
          updateIndicator("pending", "Sign in to GitHub to finish verifying the source log...");
          await reportTabState("loading");
          return "auth";
        }

        await escalateDanger("error", "Provenance check failed", response.error);
        return "failure";
      }

      if (response.found) {
        return "success";
      }

      await escalateDanger(
        "mismatch",
        "Provenance mismatch detected",
        "The provided digest was not found inside the referenced GitHub Actions log."
      );
      return "failure";
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      await escalateDanger("error", "Provenance error", message);
      return "failure";
    }
  }

  async function reportTabState(state: TabVisualState) {
    try {
      await chrome.runtime.sendMessage({
        type: "REPORT_TAB_STATE",
        state,
        url: window.location.href
      });
    } catch (error) {
      console.warn("Unable to report tab state", error);
    }
  }

  async function reportSourceSummary(hasSource: boolean, portalUrl?: string) {
    try {
      await chrome.runtime.sendMessage<ReportSourceSummaryMessage, unknown>({
        type: "REPORT_SOURCE_SUMMARY",
        hasSource,
        portalUrl
      });
    } catch (error) {
      console.warn("Unable to report source summary", error);
    }
  }

  function applyIntegrityFragment(
    algorithm: AlgorithmIdentifier,
    encoding: ContentVerificationEncoding,
    digest: string
  ) {
    const normalizedAlgorithm = algorithmIdentifierToFragment(algorithm);
    const url = new URL(window.location.href);
    const hashPayload = url.hash.startsWith("#") ? url.hash.slice(1) : url.hash;
    const params = new URLSearchParams(hashPayload);
    params.set("integrity", `${normalizedAlgorithm}-${digest}`);

    const nextHash = params.toString();
    const nextUrl = `${url.origin}${url.pathname}${url.search}${nextHash ? `#${nextHash}` : ""}`;

    if (typeof history.replaceState === "function") {
      history.replaceState(null, document.title, nextUrl);
    } else {
      window.location.replace(nextUrl);
    }
  }

  function parseIntegrityDescriptor(hash: string): IntegrityDescriptor | null {
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

    const encoding: ContentVerificationEncoding = inferEncoding(rawDigest);
    const sourceDescriptor = parseSourceDescriptor(params.get("integrity-src"));

    return {
      algorithm: normalizedAlgorithm,
      encoding,
      digest: rawDigest.trim(),
      label: normalizedAlgorithm.toUpperCase(),
      source: sourceDescriptor
    };
  }

  function parseSourceDescriptor(value: string | null): SourceDescriptor | null {
    if (!value) {
      return null;
    }

    const parts = value.split(":").map((segment) => segment.trim());
    if (parts.length !== 4) {
      return null;
    }

    const [providerCode, repo, runId, jobId] = parts;
    if (!providerCode || !repo || !runId || !jobId) {
      return null;
    }

    if (providerCode !== "gh" && providerCode !== "github") {
      console.warn("Unsupported source provider", providerCode);
      return null;
    }

    const cleanRepo = repo.replace(/^github\.com\//u, "");
    if (!cleanRepo.includes("/")) {
      return null;
    }

    const portalUrl = `https://github.com/${cleanRepo}/actions/runs/${runId}`;
    const logUrl = `${portalUrl}/job/${jobId}`;

    return {
      provider: "github",
      repo: cleanRepo,
      runId,
      jobId,
      portalUrl,
      logUrl
    };
  }

  function normalizeAlgorithm(value: string): string | null {
    const lookup: Record<string, string> = {
      sha256: "sha256",
      sha384: "sha384",
      sha512: "sha512"
    };

    return lookup[value.trim().toLowerCase()] ?? null;
  }

  function inferEncoding(digest: string): ContentVerificationEncoding {
    const urlSafe = /^[A-Za-z0-9-_]+$/u.test(digest);
    const hasUrlOnlyChars = !digest.includes("+") && !digest.includes("/");
    if (urlSafe && hasUrlOnlyChars) {
      return "base64url";
    }
    return "base64";
  }

  function algorithmIdentifierToFragment(identifier: AlgorithmIdentifier): string {
    if (typeof identifier === "string") {
      return sanitizeAlgorithmToken(identifier);
    }

    if (typeof identifier === "object" && "name" in identifier && typeof identifier.name === "string") {
      return sanitizeAlgorithmToken(identifier.name);
    }

    return DEFAULT_ALGORITHM;
  }

  function sanitizeAlgorithmToken(value: string): string {
    const clean = value.toLowerCase().replace(/[^a-z0-9]/gu, "");
    if (clean === "sha256" || clean === "sha384" || clean === "sha512") {
      return clean;
    }
    return DEFAULT_ALGORITHM;
  }

  type IndicatorState = "pending" | "match" | "mismatch" | "error" | "absent";

  type Indicator = {
    root: HTMLDivElement;
    message: HTMLSpanElement;
    sourceBadge: HTMLSpanElement;
  };

  function createIndicator(): Indicator {
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
    } as CSSStyleDeclaration);

    const statusDot = document.createElement("span");
    statusDot.id = "web-integrity-indicator-dot";
    Object.assign(statusDot.style, {
      width: "0.5rem",
      height: "0.5rem",
      borderRadius: "999px",
      display: "inline-block"
    } as CSSStyleDeclaration);

    const sourceBadge = document.createElement("span");
    sourceBadge.id = "web-integrity-indicator-source";
    Object.assign(sourceBadge.style, {
      padding: "0.2rem 0.65rem",
      borderRadius: "999px",
      background: "rgba(15, 23, 42, 0.1)",
      color: "#0f172a",
      fontSize: "0.7rem",
      fontWeight: "600",
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      display: "none"
    } as Partial<CSSStyleDeclaration>);

    const message = document.createElement("span");
    message.id = "web-integrity-indicator-message";

    root.append(statusDot, sourceBadge, message);
    document.documentElement.append(root);

    return { root, message, sourceBadge };
  }

  function updateIndicator(state: IndicatorState, text: string) {
    const dot = document.getElementById("web-integrity-indicator-dot") as HTMLSpanElement | null;
    if (!indicator.root || !indicator.message || !dot) {
      return;
    }

    indicator.root.style.display = "flex";
    indicator.message.textContent = text;

    const palette: Record<IndicatorState, string> = {
      pending: "#f5a524",
      match: "#12a454",
      mismatch: "#c44536",
      error: "#c44536",
      absent: "#6b7280"
    };

    dot.style.backgroundColor = palette[state];

    if (state === "match" || state === "pending" || state === "absent") {
      hideDangerOverlay();
    }
  }

  function updateSourceBadge(source: SourceDescriptor | null) {
    if (!indicator.sourceBadge) {
      return;
    }

    if (source) {
      indicator.sourceBadge.style.display = "inline-flex";
      indicator.sourceBadge.textContent = "Source · GitHub";
      indicator.root.style.borderColor = "rgba(14, 165, 233, 0.6)";
      indicator.root.dataset.hasSource = "true";
    } else {
      indicator.sourceBadge.style.display = "none";
      indicator.root.style.borderColor = "rgba(0, 0, 0, 0.1)";
      delete indicator.root.dataset.hasSource;
    }
  }

  async function escalateDanger(state: IndicatorState, title: string, description: string) {
    updateIndicator(state, description);
    showDangerOverlay(title, description);
    await reportTabState("rejected");

    try {
      await chrome.runtime.sendMessage({
        type: "SHOW_DANGER_ALERT",
        title,
        message: description,
        url: window.location.href
      });
    } catch (error) {
      console.warn("Unable to escalate danger alert", error);
    }
  }

  type DangerOverlay = {
    root: HTMLDivElement;
    title: HTMLHeadingElement;
    description: HTMLParagraphElement;
  };

  function createDangerOverlay(): DangerOverlay {
    const root = document.createElement("div");
    root.id = "web-integrity-danger-overlay";
    Object.assign(root.style, {
      position: "fixed",
      inset: "0",
      background: "rgba(4, 16, 19, 0.92)",
      color: "#fff",
      zIndex: "2147483647",
      display: "none",
      alignItems: "center",
      justifyContent: "center",
      padding: "2rem"
    } as CSSStyleDeclaration);

    const panel = document.createElement("div");
    Object.assign(panel.style, {
      maxWidth: "32rem",
      width: "100%",
      background: "rgba(255, 255, 255, 0.05)",
      border: "1px solid rgba(255, 255, 255, 0.2)",
      borderRadius: "1rem",
      padding: "2rem",
      boxShadow: "0 30px 80px rgba(0, 0, 0, 0.45)",
      backdropFilter: "blur(6px)",
      textAlign: "center"
    } as CSSStyleDeclaration);

    const title = document.createElement("h2");
    title.textContent = "Integrity violation";
    Object.assign(title.style, {
      fontSize: "1.5rem",
      marginBottom: "0.75rem"
    } as CSSStyleDeclaration);

    const description = document.createElement("p");
    Object.assign(description.style, {
      marginBottom: "1.5rem",
      lineHeight: "1.5"
    } as Partial<CSSStyleDeclaration>);

    const buttonRow = document.createElement("div");
    Object.assign(buttonRow.style, {
      display: "flex",
      gap: "0.75rem",
      justifyContent: "center"
    } as Partial<CSSStyleDeclaration>);

    const dismissButton = document.createElement("button");
    dismissButton.textContent = "Dismiss warning";
    Object.assign(dismissButton.style, {
      padding: "0.75rem 1.5rem",
      borderRadius: "999px",
      border: "none",
      cursor: "pointer",
      fontSize: "1rem",
      fontWeight: "600",
      background: "#ffffff",
      color: "#0f172a"
    } as Partial<CSSStyleDeclaration>);
    dismissButton.addEventListener("click", hideDangerOverlay);

    const reloadButton = document.createElement("button");
    reloadButton.textContent = "Reload page";
    Object.assign(reloadButton.style, {
      padding: "0.75rem 1.5rem",
      borderRadius: "999px",
      border: "1px solid rgba(255, 255, 255, 0.4)",
      background: "transparent",
      color: "#fff",
      cursor: "pointer",
      fontSize: "1rem"
    } as Partial<CSSStyleDeclaration>);
    reloadButton.addEventListener("click", () => window.location.reload());

    buttonRow.append(reloadButton, dismissButton);
    panel.append(title, description, buttonRow);
    root.append(panel);
    document.documentElement.append(root);

    return { root, title, description };
  }

  function showDangerOverlay(title: string, description: string) {
    dangerOverlay.title.textContent = title;
    dangerOverlay.description.textContent = description;
    dangerOverlay.root.style.display = "flex";
  }

  function hideDangerOverlay() {
    dangerOverlay.root.style.display = "none";
  }
})();
