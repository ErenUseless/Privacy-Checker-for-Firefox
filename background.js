// background.js
// Runs as a persistent background script (MV2).
// Responsibilities:
//   1. Cache HTTP response headers per tab            → Sec3
//   2. Match third-party domains against tracker list → S2, S3, D1, P1, P2
//   3. Fetch & analyse the privacy policy page        → T3, D2, R1, R2, R3
//   4. Run the scoring engine against all rule weights
//   5. Respond to ANALYZE messages from popup.js

"use strict";

// ─── State ────────────────────────────────────────────────────────────────────

/** @type {TrackerEntry[]} Loaded once from tracker_list.json. */
let TRACKER_LIST = [];

const CORPORATE_FAMILIES = {
  google: [
    "youtube.com", "google.com", "gmail.com", "blogger.com",
    "google.com.tr"
  ],
  meta: [
    "facebook.com", "instagram.com", "whatsapp.com", "threads.net"
  ],
  microsoft: [
    "bing.com", "microsoft.com", "outlook.com", "linkedin.com",
    "github.com", "office.com"
  ],
  amazon: [
    "amazon.com", "twitch.tv", "imdb.com", "amazon.com.tr"
  ],
  twitter: [
    "twitter.com", "x.com"
  ]
};

const TRACKER_OWNERS = {
  google: [
    "google-analytics.com", "googletagmanager.com", "googletagservices.com",
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "adwords.google.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "ajax.googleapis.com", "apis.google.com", "youtube.com",
    "googlevideo.com", "yt3.ggpht.com", "ytimg.com"
  ],
  meta: [
    "connect.facebook.net", "facebook.com", "instagram.com",
    "fbcdn.net", "fbsbx.com"
  ],
  microsoft: [
    "clarity.ms", "bat.bing.com", "bing.com", "linkedin.com",
    "platform.linkedin.com", "snap.licdn.com"
  ],
  amazon: [
    "amazon-adsystem.com", "assoc-amazon.com"
  ],
  twitter: [
    "platform.twitter.com", "syndication.twitter.com", "ads.twitter.com"
  ]
};

/**
 * Per-tab header cache.  Populated by webRequest.onHeadersReceived.
 * Shape: { [tabId]: browser.webRequest.HttpHeader[] }
 */
const HEADER_CACHE = {};

/** Badge background colours — must match GRADE_COLOR in popup.js exactly. */
const GRADE_BADGE_COLORS = {
  A: "#00e5a0",
  B: "#6dffb3",
  C: "#ffb020",
  D: "#ff7a40",
  F: "#ff4466",
};

// ─── Startup: load tracker list ───────────────────────────────────────────────

fetch(browser.runtime.getURL("tracker_list.json"))
  .then(r => r.json())
  .then(data => {
    TRACKER_LIST = data;
    console.log(`[Privacy Checker] Loaded ${TRACKER_LIST.length} tracker entries.`);
  })
  .catch(err => console.error("[Privacy Checker] Failed to load tracker_list.json:", err));

// ─── Sec3: Cache response headers for every main-frame navigation ─────────────

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type === "main_frame") {
      HEADER_CACHE[details.tabId] = details.responseHeaders || [];
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

browser.tabs.onRemoved.addListener((tabId) => {
  delete HEADER_CACHE[tabId];
  browser.browserAction.setBadgeText({ text: "", tabId }).catch(() => {});
});

// Feature 21: Clear badge when tab starts a new navigation
browser.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    browser.browserAction.setBadgeText({ text: "", tabId }).catch(() => {});
  }
});

// ─── Message router ───────────────────────────────────────────────────────────

browser.runtime.onMessage.addListener((message, sender) => {
  if (!message || !message.type) return false;

  if (message.type === "ANALYZE") {
    return handleAnalyze(message.rawData, message.tabId, message.hostname);
  }

  if (message.type === "GET_HEADERS") {
    return Promise.resolve({ headers: HEADER_CACHE[message.tabId] || [] });
  }
});

// ─── Main analysis orchestrator ───────────────────────────────────────────────

async function handleAnalyze(rawData, tabId, hostname) {
  // Guard against a missing or partial response from the content script.
  // Each sub-object is normalised to a safe default so no downstream function
  // needs to defensively check for undefined properties.
  if (!rawData || typeof rawData !== "object") {
    throw new Error("No data received from content script.");
  }
  rawData.scripts      = rawData.scripts      || { thirdPartyDomains: [], resourceCount: 0, resources: [] };
  rawData.scripts.thirdPartyDomains = Array.isArray(rawData.scripts.thirdPartyDomains)
    ? rawData.scripts.thirdPartyDomains : [];
  rawData.privacyPolicy = rawData.privacyPolicy || { found: false, url: null, inFooter: false, linkText: null };
  rawData.cookieBanner  = rawData.cookieBanner  || { found: false, hasRejectOption: false, hasPreChecked: false, hasWithdrawal: false };
  rawData.security      = rawData.security      || { isHTTPS: false, hasMixedContent: false, mixedContent: [] };
  rawData.forms         = rawData.forms         || { formCount: 0, hasForms: false, hasPIIFields: false, piiFields: [], thirdPartyActions: [], insecureForms: [], forms: [] };
  rawData.childContent  = rawData.childContent  || { isChildDirected: false, confidence: "none", signals: [] };

  const trackerData    = matchTrackers(rawData.scripts.thirdPartyDomains, hostname || "");
  const policyAnalysis = await fetchAndAnalyzePolicy(rawData.privacyPolicy);
  const secHeaders     = analyzeSecurityHeaders(HEADER_CACHE[tabId] || []);
  const cookieAnalysis = await analyzeCookies(tabId);
  const { ruleResults, totalScore, maxScore, grade } =
    scoreResults(rawData, trackerData, policyAnalysis, secHeaders, cookieAnalysis);

  // Feature 21: Update toolbar badge with privacy grade
  const badgeColor = GRADE_BADGE_COLORS[grade] || "#5a6175";
  browser.browserAction.setBadgeText({ text: grade, tabId }).catch(() => {});
  browser.browserAction.setBadgeBackgroundColor({ color: badgeColor, tabId }).catch(() => {});

  return { ruleResults, totalScore, maxScore, grade, trackerData, policyAnalysis, secHeaders, cookieAnalysis };
}

// ─── S2 / S3 / D1 / P1 / P2 — Tracker matching ───────────────────────────────

function matchTrackers(domains, currentHostname) {
  const currentRoot = currentHostname.replace(/^www\./, "");
  let siteOwner = null;
  for (const [owner, sites] of Object.entries(CORPORATE_FAMILIES)) {
    if (sites.some(s => currentRoot === s || currentRoot.endsWith("." + s))) {
      siteOwner = owner;
      break;
    }
  }

  const ownedDomains = siteOwner ? new Set(TRACKER_OWNERS[siteOwner] || []) : new Set();

  const matched = [];
  for (const domain of domains) {
    if (ownedDomains.has(domain) ||
        [...ownedDomains].some(d => domain === d || domain.endsWith("." + d))) {
      continue;
    }
    let entry = TRACKER_LIST.find(t => t.domain === domain);
    if (!entry) {
      entry = TRACKER_LIST.find(t => domain === t.domain || domain.endsWith("." + t.domain));
    }
    if (entry) {
      matched.push({ domain, ...entry });
    }
  }

  const seenNames = new Set();
  const deduped = matched.filter(m => {
    if (seenNames.has(m.name)) return false;
    seenNames.add(m.name);
    return true;
  });

  const byCategory = {};
  for (const m of deduped) {
    (byCategory[m.category] = byCategory[m.category] || []).push(m);
  }

  const EU_JURISDICTIONS = new Set(["AT","BE","BG","CY","CZ","DE","DK","EE","ES","FI","FR",
    "GR","HR","HU","IE","IT","LT","LU","LV","MT","NL","PL","PT","RO","SE","SI","SK",
    "NO","IS","LI"]);
  const internationalDomains = deduped.filter(
    m => m.jurisdiction && !EU_JURISDICTIONS.has(m.jurisdiction)
  );

  const AD_CATEGORIES = new Set(["advertising", "social"]);
  const hasBehavioralAd = deduped.some(m => AD_CATEGORIES.has(m.category));

  const adCount = (byCategory.advertising || []).length + (byCategory.social || []).length;
  let profilingRiskLevel;
  if (adCount === 0)     profilingRiskLevel = "none";
  else if (adCount <= 2) profilingRiskLevel = "low";
  else if (adCount <= 5) profilingRiskLevel = "medium";
  else                   profilingRiskLevel = "high";

  return { matched: deduped, byCategory, internationalDomains, hasBehavioralAd, profilingRiskLevel };
}

// ─── T3 / D2 / R1 / R2 / R3 — Privacy policy analysis ───────────────────────

/**
 * Multi-strategy privacy policy fetcher.
 *
 * Strategy 1 — background fetch() + DOMParser  (fast, no CSP issues, works for
 *   server-rendered HTML which covers the vast majority of policy pages).
 *
 * Strategy 2 — hidden tab + executeScript  (fallback for SPA-rendered pages
 *   like React/Next.js where Strategy 1 returns near-empty markup).
 *   Uses a longer 4-second post-load delay and up to 15-second total timeout
 *   to give JS frameworks time to fully render.
 *
 * Both strategies feed the same analyzeText() helper so scoring is consistent.
 */
async function fetchAndAnalyzePolicy(privacyPolicy) {
  if (!privacyPolicy || !privacyPolicy.found || !privacyPolicy.url) return null;

  const url = privacyPolicy.url;

  // ── Strategy 1: background fetch() ──────────────────────────────────────────
  // Background scripts bypass CORS entirely (they have <all_urls> permission),
  // so a plain fetch() works across all origins without any tab overhead.
  // This is the preferred path: fast (~1–3 s), no CSP injection risk, no tab leak.
  try {
    const controller = new AbortController();
    const fetchTimeout = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(url, {
      signal: controller.signal,
      // Mimic a real browser request so servers don't serve bot-detection pages
      headers: {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache"
      }
    });
    clearTimeout(fetchTimeout);

    if (response.ok) {
      const html = await response.text();

      // Parse with DOMParser — available in MV2 background pages (not workers)
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, "text/html");

      // Strip non-content nodes to reduce noise
      const NOISE_SELECTORS = [
        "script", "style", "noscript", "svg", "canvas",
        "nav", "header", "footer",
        "[aria-hidden='true']",
        ".cookie-banner", ".consent-banner", "#cookie-notice"
      ];
      doc.querySelectorAll(NOISE_SELECTORS.join(",")).forEach(el => el.remove());

      const rawText = (doc.body ? doc.body.innerText || doc.body.textContent : "") || "";
      const text = rawText.replace(/\s+/g, " ").trim();

      if (text.length >= 300) {
        console.log(`[Privacy Checker] Strategy 1 succeeded: ${text.length} chars from ${url}`);
        return analyzeText(text, url);
      }

      // Text too short — likely a JS-rendered SPA. Fall through to Strategy 2.
      console.log(`[Privacy Checker] Strategy 1: only ${text.length} chars — trying Strategy 2 (SPA fallback)`);
    } else {
      console.warn(`[Privacy Checker] Strategy 1: HTTP ${response.status} for ${url}`);
    }
  } catch (fetchErr) {
    console.warn(`[Privacy Checker] Strategy 1 fetch failed: ${fetchErr.message}`);
    // Don't return — fall through to Strategy 2
  }

  // ── Strategy 2: hidden tab + executeScript ───────────────────────────────────
  // Used when Strategy 1 yields too little text (SPA) or fails entirely.
  // Creates an invisible background tab, waits for full JS rendering, then
  // extracts innerText via executeScript.
  //
  // Known failure modes:
  //   • Some sites block executeScript via manifest-level CSP on the extension
  //   • Very rarely, tabs.create rejects for resource/permission reasons
  // Both are caught and returned as fetchFailed so scoring skips these rules.
  let policyTab = null;
  try {
    policyTab = await browser.tabs.create({ url, active: false });

    // Poll for tab completion instead of using onUpdated (avoids race conditions
    // where "complete" fires before the listener is registered on fast pages).
    const DEADLINE_MS  = 15000;
    const POLL_INTERVAL = 400;
    const deadline = Date.now() + DEADLINE_MS;

    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, POLL_INTERVAL));
      let tabInfo;
      try { tabInfo = await browser.tabs.get(policyTab.id); } catch { break; }
      if (tabInfo.status === "complete") break;
    }

    // Extra pause for JS frameworks (React/Vue/Angular/Next.js) to finish rendering.
    // 4 seconds is generous — most frameworks finish in under 2 s.
    await new Promise(r => setTimeout(r, 4000));

    let results;
    try {
      results = await browser.tabs.executeScript(policyTab.id, {
        // Prefer innerText (respects display:none) over textContent
        code: `
          (function() {
            var noiseSelectors = 'script,style,noscript,nav,header,footer,[aria-hidden="true"]';
            document.querySelectorAll(noiseSelectors).forEach(function(el){ el.remove(); });
            return document.body ? (document.body.innerText || document.body.textContent || '') : '';
          })()
        `
      });
    } catch (scriptErr) {
      return {
        fetchFailed: true,
        fetchReason: "script injection blocked (CSP or extension policy)",
        url
      };
    }

    const text = ((results && results[0]) || "").replace(/\s+/g, " ").trim();

    if (text.length < 100) {
      return {
        fetchFailed: true,
        fetchReason: `page rendered insufficient text (${text.length} chars)`,
        url
      };
    }

    console.log(`[Privacy Checker] Strategy 2 succeeded: ${text.length} chars from ${url}`);
    return analyzeText(text, url);

  } catch (tabErr) {
    return {
      fetchFailed: true,
      fetchReason: "tab creation failed: " + tabErr.message,
      url
    };
  } finally {
    if (policyTab) {
      browser.tabs.remove(policyTab.id).catch(() => {});
    }
  }
}

// ─── Shared policy text analyser ─────────────────────────────────────────────

/**
 * Runs keyword analysis on the extracted policy text.
 * Shared by both fetch strategies.
 *
 * @param {string} text  Cleaned plain-text content of the policy page.
 * @param {string} url   Source URL (for reporting).
 * @returns {PolicyAnalysis}
 */
function analyzeText(text, url) {
  const lower      = text.toLowerCase();
  const textLength = text.length;

  function has(...keywords) {
    return keywords.some(kw => lower.includes(kw));
  }

  // T3: Minimum content length
  const hasSubstantialContent = textLength >= 500;

  // D2: Data transfers / international sharing
  const mentionsTransfers = has(
    "transfer", "aktarım", "aktarim", "yurtdışına", "yurtdisina",
    "third parties", "üçüncü kişiler", "ucuncu kisiler",
    "cross-border", "international transfer", "data sharing",
    "third-party", "share your data", "we may share"
  );

  // R1: Data subject rights
  const mentionsRights = has(
    "right to access", "right of access", "right to erasure", "right to deletion",
    "right to rectification", "right to object", "right to portability",
    "haklarınız", "haklariniz", "erişim hakkı", "erisim hakki",
    "düzeltme", "duzeltme", "silme hakkı", "silme hakki",
    "itiraz hakkı", "itiraz hakki", "data subject rights", "your rights",
    "you have the right", "you may request", "you can request"
  );

  // R2: DPO / contact info
  const EMAIL_REGEX = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
  const emailMatches = text.match(EMAIL_REGEX) || [];
  const hasDPOContact = emailMatches.length > 0 || has(
    "data protection officer", "dpo", "privacy contact",
    "veri koruma görevlisi", "kvkk başvuru", "kvkk basvuru",
    "iletisim", "iletişim", "contact us for privacy",
    "privacy@", "gdpr@", "legal@", "contact us", "reach us"
  );

  // R3: Controller identification
  const mentionsController = has(
    "data controller", "controller", "veri sorumlusu",
    "ltd.", "llc", "inc.", "a.ş.", "a.s.", "limited şirketi", "anonim şirketi",
    "company name", "registered", "corporation", "gmbh", "s.r.o.", "s.a."
  );

  return {
    url,
    textLength,
    hasSubstantialContent,
    mentionsTransfers,
    mentionsRights,
    hasDPOContact,
    mentionsController,
    emailsFound: emailMatches
  };
}

// ─── Sec3 — Security header analysis ─────────────────────────────────────────

function analyzeSecurityHeaders(headers) {
  const headerMap = {};
  for (const h of headers) {
    headerMap[h.name.toLowerCase()] = h.value;
  }

  const hasCSP    = "content-security-policy" in headerMap;
  const hasHSTS   = "strict-transport-security" in headerMap;
  const hasXFrame = "x-frame-options" in headerMap;

  const summary = [];
  if (hasCSP)    summary.push("Content-Security-Policy: " + headerMap["content-security-policy"]);
  if (hasHSTS)   summary.push("Strict-Transport-Security: " + headerMap["strict-transport-security"]);
  if (hasXFrame) summary.push("X-Frame-Options: " + headerMap["x-frame-options"]);

  return { hasCSP, hasHSTS, hasXFrame, summary };
}

// ─── K1 / K2 / K3 / K4 — Cookie analysis ────────────────────────────────────

async function analyzeCookies(tabId) {
  let tabUrl;
  try {
    const tab = await browser.tabs.get(tabId);
    tabUrl = tab.url;
  } catch {
    return null;
  }

  if (!tabUrl || (!tabUrl.startsWith("http://") && !tabUrl.startsWith("https://"))) {
    return null;
  }

  let cookies;
  try {
    cookies = await browser.cookies.getAll({ url: tabUrl });
  } catch (err) {
    console.error("[Privacy Checker] browser.cookies.getAll failed:", err);
    return null;
  }

  const nowSeconds = Date.now() / 1000;

  const PURPOSE_PATTERNS = [
    { re: /^(_ga$|_gid$|_gat_|__utm)/i,             category: "analytics",   provider: "Google Analytics" },
    { re: /^(_fbp$|_fbc$|fbm_|fbsr_)/i,              category: "advertising", provider: "Facebook" },
    { re: /^(IDE$|DSID$|FLC$|AID$|TAID$)/,           category: "advertising", provider: "Google Ads" },
    { re: /^(CONSENT$|NID$|SID$|HSID$|SSID$)/,       category: "analytics",   provider: "Google" },
    { re: /^(_hjid|_hjSession|_hjAbsoluteSession)/i,  category: "analytics",   provider: "Hotjar" },
    { re: /^mp_/i,                                    category: "analytics",   provider: "Mixpanel" },
    { re: /^ajs_/i,                                   category: "analytics",   provider: "Segment" },
    { re: /cookie.?consent|cookieconsent|cc_cookie/i, category: "cmp",         provider: "Consent Manager" },
    { re: /^(PHPSESSID$|JSESSIONID$|sess_|session)/i, category: "necessary",   provider: "Session" },
    { re: /^(csrf|_csrf|xsrf)/i,                      category: "necessary",   provider: "CSRF Protection" },
    { re: /^(auth_|access_token|jwt_|refresh_token)/i,category: "necessary",   provider: "Authentication" },
    { re: /^(cart_|basket_|checkout_)/i,               category: "necessary",   provider: "E-commerce" },
  ];

  function classifyCookie(name) {
    for (const { re, category, provider } of PURPOSE_PATTERNS) {
      if (re.test(name)) return { category, provider };
    }
    return { category: "unknown", provider: null };
  }

  const evaluated = cookies.map(c => {
    const { category, provider } = classifyCookie(c.name);

    const securityIssues = [];
    if (!c.secure)                        securityIssues.push("missing Secure flag");
    if (!c.httpOnly)                      securityIssues.push("missing HttpOnly flag");
    if (c.sameSite === "no_restriction")  securityIssues.push("SameSite=None");

    let lifetimeDays = null;
    let lifetimeLabel = "session";
    if (!c.session && c.expirationDate) {
      lifetimeDays = Math.round((c.expirationDate - nowSeconds) / 86400);
      if      (lifetimeDays <= 0)   lifetimeLabel = "expired";
      else if (lifetimeDays <= 30)  lifetimeLabel = "< 30 days";
      else if (lifetimeDays <= 365) lifetimeLabel = "30\u2013365 days";
      else                          lifetimeLabel = "> 1 year";
    }

    return { name: c.name, domain: c.domain, session: c.session,
             secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite,
             lifetimeDays, lifetimeLabel, securityIssues, category, provider };
  });

  const insecureCookies = evaluated.filter(c => !c.session && c.securityIssues.length > 0);
  const persistentCount = evaluated.filter(c => !c.session).length;
  const k2Pass = persistentCount === 0 ||
    (insecureCookies.length / persistentCount) < 0.2;

  const longLivedCookies = evaluated.filter(
    c => !c.session && c.lifetimeDays !== null && c.lifetimeDays > 365
  );
  const k3Pass = longLivedCookies.length === 0;

  const unknownCount = evaluated.filter(c => c.category === "unknown").length;
  const k4Pass = evaluated.length === 0 || (unknownCount / evaluated.length) < 0.3;

  const catCounts = evaluated.reduce((acc, c) => {
    acc[c.category] = (acc[c.category] || 0) + 1; return acc;
  }, {});
  const catSummaryStr = Object.entries(catCounts)
    .map(([cat, n]) => `${n} ${cat}`).join(", ") || "none";

  const result = {
    count: evaluated.length,
    cookies: evaluated,
    k2: {
      pass: k2Pass,
      insecureCookies,
      detail: k2Pass
        ? `${evaluated.length} cookie(s) checked — security attributes look adequate.`
        : `${insecureCookies.length} of ${persistentCount} persistent cookie(s) have issues: ` +
          insecureCookies.slice(0, 3).map(c => `${c.name} (${c.securityIssues.join(", ")})`).join("; ") + "."
    },
    k3: {
      pass: k3Pass,
      longLivedCookies,
      detail: k3Pass
        ? "No cookies exceed a 1-year lifetime."
        : `${longLivedCookies.length} long-lived cookie(s): ` +
          longLivedCookies.slice(0, 3).map(c => `${c.name} (~${c.lifetimeDays} days)`).join(", ") + "."
    },
    k4: {
      pass: k4Pass,
      detail: `${evaluated.length} cookie(s) classified: ${catSummaryStr}.` +
        (unknownCount > 0 ? ` ${unknownCount} unrecognised.` : "")
    }
  };

  return result;
}

// ─── Scoring engine ───────────────────────────────────────────────────────────

function scoreResults(rawData, trackerData, policyAnalysis, secHeaders, cookieAnalysis) {
  const { privacyPolicy, cookieBanner, scripts, security, forms } = rawData;
  const policy   = policyAnalysis;
  const cookies  = cookieAnalysis;

  const banner = cookieBanner || {};

  const piiWithInsecureForms =
    forms.hasPIIFields && (forms.insecureForms.length > 0 || forms.thirdPartyActions.length > 0);

  const policyFetchFailed = !!(policy && policy.fetchFailed);
  const policyAvailable   = !!(policy && !policy.fetchFailed);

  const rules = [
    // ── Transparency ──
    {
      id: "T1",
      weight: 15,
      pass: !!privacyPolicy.found,
      detail: privacyPolicy.found
        ? `A privacy policy was found on this page ("${privacyPolicy.linkText}"). This tells you how your data is collected and used.`
        : "No privacy policy was found. Without one, you have no way of knowing how this site uses your data."
    },
    {
      id: "T2",
      weight: 5,
      pass: !!(privacyPolicy.found && privacyPolicy.inFooter),
      detail: privacyPolicy.found
        ? privacyPolicy.inFooter
          ? "The privacy policy link is in the footer, where people expect to find it."
          : "A privacy policy exists, but it's not in the footer — it may be hard to find."
        : "No privacy policy was found, so we can't check where it's placed."
    },
    {
      id: "T3",
      weight: policyFetchFailed ? 0 : 5,
      skipped: policyFetchFailed,
      pass: !!(policyAvailable && policy.hasSubstantialContent),
      detail: policyAvailable
        ? policy.hasSubstantialContent
          ? `The privacy policy appears detailed and informative (${policy.textLength.toLocaleString()} characters).`
          : `The privacy policy is very short (${policy.textLength.toLocaleString()} characters) — it may not cover everything required by law.`
        : policyFetchFailed
          ? `We couldn't read the privacy policy page — skipping this check.`
          : "No privacy policy was found to check."
    },

    // ── Consent ──
    {
      id: "C1",
      weight: 15,
      pass: !!banner.found,
      detail: banner.found
        ? "A cookie consent notice was shown — the site is asking for your permission."
        : "No cookie consent popup was found. Sites using tracking cookies should ask your permission first."
    },
    {
      id: "C2",
      weight: 15,
      pass: !!(banner.found && banner.hasRejectOption),
      detail: banner.found
        ? banner.hasRejectOption
          ? "The consent popup lets you choose which cookies to accept — you're not forced to accept everything."
          : "The consent popup only had an 'Accept All' option with no way to say no or customise your choices."
        : "No consent popup was found, so this couldn't be evaluated."
    },
    {
      id: "C3",
      weight: 10,
      pass: !(banner.found && banner.hasPreChecked),
      detail: banner.hasPreChecked
        ? "Non-essential tracking options were pre-ticked in the cookie popup. Under GDPR, consent must be freely given — not assumed."
        : banner.found
          ? "Nothing was sneakily pre-selected in the cookie popup. Good."
          : "No consent popup was found, so pre-ticking couldn't be checked."
    },
    {
      id: "C4",
      weight: 10,
      pass: !!banner.hasWithdrawal,
      detail: banner.hasWithdrawal
        ? "You can change or withdraw your cookie choices at any time — a settings link is available."
        : "No way to change cookie preferences after closing the popup was found. You should always be able to change your mind."
    },

    // ── Cookies ──
    {
      id: "K1",
      weight: 0,
      pass: true,
      detail: cookies
        ? `${cookies.count} cookie${cookies.count !== 1 ? "s" : ""} found stored on your browser for this site.`
        : "Cookie information couldn't be retrieved (browser API error or non-HTTP page)."
    },
    {
      id: "K2",
      weight: 10,
      pass: !!(cookies && cookies.k2.pass),
      detail: cookies
        ? cookies.k2.pass
          ? `Cookies appear to have proper security settings in place.`
          : `Some cookies are missing security protections, which could make them easier to steal. ` +
            cookies.k2.insecureCookies.slice(0, 3).map(c => `"${c.name}" (${c.securityIssues.join(", ")})`).join("; ") + "."
        : "Cookie security couldn't be evaluated."
    },
    {
      id: "K3",
      weight: 10,
      pass: !!(cookies && cookies.k3.pass),
      detail: cookies
        ? cookies.k3.pass
          ? "No cookies are set to last longer than a year — good."
          : `${cookies.k3.longLivedCookies.length} cookie${cookies.k3.longLivedCookies.length !== 1 ? "s" : ""} will track you for over a year: ` +
            cookies.k3.longLivedCookies.slice(0, 3).map(c => `"${c.name}" (~${c.lifetimeDays} days)`).join(", ") + "."
        : "Cookie lifetimes couldn't be evaluated."
    },
    {
      id: "K4",
      weight: 5,
      pass: !!(cookies && cookies.k4.pass),
      detail: cookies
        ? cookies.k4.detail
            .replace(/cookie\(s\) classified/, "cookies identified by purpose")
            .replace(/unrecognised/, "whose purpose we couldn't determine")
        : "Cookie purposes couldn't be identified."
    },

    // ── Third-party scripts ──
    {
      id: "S2",
      weight: 20,
      pass: trackerData.matched.length === 0,
      detail: trackerData.matched.length === 0
        ? "No known tracking companies were found on this page."
        : `${trackerData.matched.length} tracking ${trackerData.matched.length === 1 ? "company was" : "companies were"} found watching your activity: ${trackerData.matched.map(m => m.name).join(", ")}.`
    },
    {
      id: "S3",
      weight: 5,
      pass: scripts.thirdPartyDomains.length === 0 ||
        trackerData.matched.length === scripts.thirdPartyDomains.length,
      detail: scripts.thirdPartyDomains.length === 0
        ? "This page loads no content from external websites."
        : `This page loaded content from ${scripts.thirdPartyDomains.length} external website${scripts.thirdPartyDomains.length !== 1 ? "s" : ""}. ` +
          `We recognised ${trackerData.matched.length}; ${scripts.thirdPartyDomains.length - trackerData.matched.length} are unknown.`
    },

    // ── Forms ──
    {
      id: "F1",
      weight: 5,
      pass: !forms.hasForms || !forms.hasPIIFields,
      detail: forms.hasForms
        ? forms.hasPIIFields
          ? `${forms.formCount} form${forms.formCount !== 1 ? "s" : ""} found, including fields that collect personal information (like your name or email).`
          : `${forms.formCount} form${forms.formCount !== 1 ? "s" : ""} found, but none appear to collect personal information.`
        : "No forms were found on this page."
    },
    {
      id: "F2",
      weight: 15,
      pass: !forms.hasPIIFields || !piiWithInsecureForms,
      detail: forms.hasPIIFields
        ? piiWithInsecureForms
          ? `Personal information fields (${forms.piiFields.map(f => f.matchedPattern).join(", ")}) were found, but the form may not protect your data properly.`
          : `Personal information fields (${forms.piiFields.map(f => f.matchedPattern).join(", ")}) were found and appear to be handled securely.`
        : "No personal information fields were detected on this page."
    },
    {
      id: "F3",
      weight: 15,
      pass: forms.thirdPartyActions.length === 0,
      detail: forms.thirdPartyActions.length === 0
        ? "Form submissions stay on this website — your data isn't sent to outside companies."
        : `${forms.thirdPartyActions.length} form${forms.thirdPartyActions.length !== 1 ? "s" : ""} send your data to external companies: ${forms.thirdPartyActions.map(f => f.domain).join(", ")}.`
    },
    {
      id: "F4",
      weight: 15,
      pass: forms.insecureForms.length === 0,
      detail: forms.insecureForms.length === 0
        ? "All forms send data over a secure, encrypted connection."
        : `${forms.insecureForms.length} form${forms.insecureForms.length !== 1 ? "s" : ""} send data over an unencrypted connection — your information could be intercepted.`
    },

    // ── Security ──
    {
      id: "Sec1",
      weight: 15,
      pass: !!security.isHTTPS,
      detail: security.isHTTPS
        ? "This page uses a secure, encrypted connection (HTTPS) — your data is protected in transit."
        : "This page uses an unencrypted connection (HTTP). Anyone on the same network could see what you're doing."
    },
    {
      id: "Sec2",
      weight: 10,
      pass: !security.hasMixedContent,
      detail: security.hasMixedContent
        ? `${security.mixedContent.length} resource${security.mixedContent.length !== 1 ? "s" : ""} on this page load insecurely, even though the main page is encrypted. This weakens your security.`
        : "Everything on this page loads securely — no unencrypted resources were found."
    },
    {
      id: "Sec3",
      weight: 5,
      pass: secHeaders.hasCSP || secHeaders.hasHSTS || secHeaders.hasXFrame,
      detail: secHeaders.summary.length > 0
        ? "This site uses extra server-side security settings that protect against common web attacks (" + secHeaders.summary.map(s => s.split(":")[0]).join(", ") + ")."
        : "This site is missing recommended security settings that help defend against common attacks."
    },

    // ── Data transfers ──
    {
      id: "D1",
      weight: 10,
      pass: trackerData.internationalDomains.length === 0,
      detail: trackerData.internationalDomains.length === 0
        ? "No services were found that appear to send your data outside the EU/EEA."
        : `${trackerData.internationalDomains.length} service${trackerData.internationalDomains.length !== 1 ? "s" : ""} may transfer your data to other countries (e.g. the US): ` +
          trackerData.internationalDomains.slice(0, 5).map(d => `${d.name} (${d.jurisdiction})`).join(", ") + `. This requires legal safeguards under GDPR.`
    },
    {
      id: "D2",
      weight: policyFetchFailed ? 0 : 5,
      skipped: policyFetchFailed,
      pass: !!(policyAvailable && policy.mentionsTransfers),
      detail: policyAvailable
        ? policy.mentionsTransfers
          ? "The privacy policy explains when and how your data is shared with third parties."
          : "The privacy policy doesn't mention data sharing or transfers — this information is required by law."
        : policyFetchFailed
          ? "We couldn't read the privacy policy page — skipping this check."
          : "No privacy policy was found to check."
    },

    // ── Data subject rights ──
    {
      id: "R1",
      weight: policyFetchFailed ? 0 : 10,
      skipped: policyFetchFailed,
      pass: !!(policyAvailable && policy.mentionsRights),
      detail: policyAvailable
        ? policy.mentionsRights
          ? "The privacy policy explains your rights — such as requesting access to or deletion of your personal data."
          : "The privacy policy doesn't explain your rights (e.g. the right to see or delete your data). This is required under GDPR."
        : policyFetchFailed
          ? "We couldn't read the privacy policy page — skipping this check."
          : "No privacy policy was found to check."
    },
    {
      id: "R2",
      weight: policyFetchFailed ? 0 : 10,
      skipped: policyFetchFailed,
      pass: !!(policyAvailable && policy.hasDPOContact),
      detail: policyAvailable
        ? policy.hasDPOContact
          ? `Contact details for privacy questions are available in the policy. Email${policy.emailsFound.length !== 1 ? "s" : ""} found: ${policy.emailsFound.slice(0, 3).join(", ")}.`
          : "No contact information for privacy questions was found in the policy. You should always be able to reach someone about your data."
        : policyFetchFailed
          ? "We couldn't read the privacy policy page — skipping this check."
          : "No privacy policy was found to check."
    },
    {
      id: "R3",
      weight: policyFetchFailed ? 0 : 10,
      skipped: policyFetchFailed,
      pass: !!(policyAvailable && policy.mentionsController),
      detail: policyAvailable
        ? policy.mentionsController
          ? "The privacy policy clearly states which company or organisation is responsible for your data."
          : "The privacy policy doesn't clearly name who is legally responsible for your data — this is a legal requirement."
        : policyFetchFailed
          ? "We couldn't read the privacy policy page — skipping this check."
          : "No privacy policy was found to check."
    },

    // ── Risk ──
    {
      id: "P1",
      weight: 20,
      pass: trackerData.profilingRiskLevel === "none" || trackerData.profilingRiskLevel === "low",
      detail: {
        none:   "No signs of your browsing behaviour being tracked for advertising.",
        low:    `Low advertising risk: just ${(trackerData.byCategory.advertising || []).length + (trackerData.byCategory.social || []).length} ad or social tracker${((trackerData.byCategory.advertising || []).length + (trackerData.byCategory.social || []).length) !== 1 ? "s" : ""} found.`,
        medium: "Several advertising trackers are present — companies may be building a profile of your interests.",
        high:   "Many advertising trackers are present — your browsing activity is very likely being profiled and used for targeted ads."
      }[trackerData.profilingRiskLevel]
    },
    {
      id: "P2",
      weight: 10,
      pass: !trackerData.hasBehavioralAd,
      detail: trackerData.hasBehavioralAd
        ? `These companies use your browsing data to show you targeted ads: ${[...(trackerData.byCategory.advertising || []), ...(trackerData.byCategory.social || [])].map(t => t.name).join(", ")}.`
        : "No targeted advertising companies were found on this page."
    },
    {
      id: "P3",
      weight: 5,
      pass: (() => {
        const child = rawData.childContent;
        if (!child || !child.isChildDirected) return true;
        return trackerData.matched.length === 0;
      })(),
      detail: (() => {
        const child = rawData.childContent;
        if (!child) return "Child-content detection data unavailable.";
        if (!child.isChildDirected) return "This page doesn't appear to be aimed at children.";
        const signalList = child.signals.slice(0, 3).join("; ");
        const trackerCount = trackerData.matched.length;
        if (trackerCount === 0) {
          return `This page may be aimed at children (${child.confidence} confidence) but no trackers were found — good. Signals: ${signalList}.`;
        }
        return `This page appears to target children (${child.confidence} confidence) and has ${trackerCount} tracker${trackerCount !== 1 ? "s" : ""} — this raises serious legal concerns under GDPR. Signals: ${signalList}.`;
      })()
    }
  ];

  // ── Weighted score calculation ──
  let earnedPoints = 0;
  let maxPoints    = 0;

  for (const rule of rules) {
    maxPoints += rule.weight;

    if (rule.pass) {
      if (rule.id === "S2") {
        const count = trackerData.matched.length;
        if (count === 0)      earnedPoints += rule.weight;
        else if (count <= 3)  earnedPoints += Math.round(rule.weight * 0.5);
      } else if (rule.id === "P1") {
        earnedPoints += trackerData.profilingRiskLevel === "none"
          ? rule.weight
          : Math.round(rule.weight * 0.5);
      } else {
        earnedPoints += rule.weight;
      }
    }
  }

  const totalScore = maxPoints > 0 ? Math.round((earnedPoints / maxPoints) * 100) : 0;

  const grade =
    totalScore >= 85 ? "A" :
    totalScore >= 70 ? "B" :
    totalScore >= 55 ? "C" :
    totalScore >= 40 ? "D" : "F";

  return { ruleResults: rules, totalScore, maxScore: maxPoints, grade };
}