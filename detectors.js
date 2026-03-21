// detectors.js
// Implements detection functions for each rule category defined in rules.json.
// NOTE: Content scripts in MV2 do not support ES module syntax.
// If you load this as a plain content script (not via import), remove the
// `export` keywords and list both files under content_scripts in manifest.json.
// Alternatively, bundle with esbuild/webpack to keep the import in content.js.

// ─── Shared helpers ──────────────────────────────────────────────────────────

/** Returns the hostname of the current page. */
function currentHost() {
  return window.location.hostname.replace(/^www\./, "");
}

/**
 * Checks if a URL belongs to a different domain than the current page.
 * Subdomains of the same root are treated as first-party.
 */
function isThirdParty(url) {
  try {
    const host = new URL(url, window.location.href).hostname.replace(/^www\./, "");
    const own = currentHost();
    // same host or a subdomain of own
    return host !== own && !host.endsWith("." + own);
  } catch {
    return false;
  }
}

/** Extracts the hostname from a URL string, or null on failure. */
function hostnameOf(url) {
  try {
    return new URL(url, window.location.href).hostname;
  } catch {
    return null;
  }
}

/** Returns true when an element is likely visible to the user. */
function isVisible(el) {
  const style = window.getComputedStyle(el);
  if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") {
    return false;
  }
  const rect = el.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}

// ─── T1 / T2 — Privacy policy link ───────────────────────────────────────────

/**
 * Covers rules T1 and T2.
 *
 * Returns:
 *   found        {boolean}  Whether any privacy link was detected.
 *   url          {string|null}  Href of the best candidate.
 *   inFooter     {boolean}  Whether the link is inside a <footer> element.
 *   linkText     {string|null}  Visible anchor text of the found link.
 */
function findPrivacyPolicyLink() {
  const KEYWORDS = [
    "privacy", "privacy policy",
    "gizlilik", "gizlilik politikası", "gizlilik bildirimi",
    "kvkk", "aydınlatma", "aydınlatma metni",
    "data protection", "datenschutz", "privacybeleid"
  ];

  /** Returns a score >= 0 for how confidently this anchor matches. */
  function scoreAnchor(a) {
    const text  = (a.textContent || "").trim().toLowerCase();
    const href  = (a.getAttribute("href") || "").toLowerCase();
    const title = (a.getAttribute("title") || "").toLowerCase();
    const aria  = (a.getAttribute("aria-label") || "").toLowerCase();
    let score = 0;
    for (const kw of KEYWORDS) {
      if (text.includes(kw))  score += 3;
      if (href.includes(kw))  score += 2;
      if (title.includes(kw)) score += 1;
      if (aria.includes(kw))  score += 1;
    }
    return score;
  }

  const anchors = Array.from(document.querySelectorAll("a[href]"));
  let best = null;
  let bestScore = 0;

  for (const a of anchors) {
    const s = scoreAnchor(a);
    if (s > bestScore) {
      bestScore = s;
      best = a;
    }
  }

  if (!best || bestScore === 0) {
    return { found: false, url: null, inFooter: false, linkText: null };
  }

  // T2: Check if the link lives inside a <footer> or near the page bottom.
  const inFooter =
    !!best.closest("footer") ||
    best.getBoundingClientRect().top > document.documentElement.scrollHeight * 0.75;

  return {
    found: true,
    url: best.href,
    inFooter,
    linkText: best.textContent.trim()
  };
}

// ─── C1 / C2 / C3 / C4 — Cookie / consent banner ────────────────────────────

/**
 * Covers rules C1, C2, C3, C4.
 *
 * Returns:
 *   found             {boolean}  Whether a consent banner was detected.
 *   hasRejectOption   {boolean}  Whether a reject/settings button is present (C2).
 *   hasPreChecked     {boolean}  Whether non-essential checkboxes are pre-checked (C3).
 *   hasWithdrawal     {boolean}  Whether a persistent consent-change mechanism exists (C4).
 *   bannerText        {string}   Trimmed inner text of the detected banner (for debugging).
 */
function detectCookieBanner() {
  const BANNER_KEYWORDS = [
    "cookie", "cookies", "consent", "gdpr", "kvkk",
    "privacy", "banner", "modal", "çerez", "çerezler"
  ];

  const REJECT_KEYWORDS = [
    "reject", "decline", "reddet", "refuse",
    "only necessary", "only essential", "yalnızca gerekli",
    "manage", "settings", "preferences", "customize",
    "ayarlar", "tercihler", "özelleştir"
  ];

  const ACCEPTANCE_ONLY_KEYWORDS = ["accept all", "allow all", "hepsini kabul"];

  const WITHDRAWAL_KEYWORDS = [
    "cookie settings", "change consent", "cookie preferences",
    "çerez tercihleri", "gizlilik ayarları", "manage cookies",
    "withdraw consent", "revoke"
  ];

  const BANNER_SELECTORS = [
    "[id*='cookie']", "[id*='consent']", "[id*='gdpr']", "[id*='privacy']",
    "[id*='kvkk']", "[id*='banner']",
    "[class*='cookie']", "[class*='consent']", "[class*='gdpr']",
    "[class*='privacy']", "[class*='kvkk']", "[class*='banner']",
    "#onetrust-banner-sdk", "#cookiescript_injected",
    "#CybotCookiebotDialog", ".cc-window", "#qc-cmp2-container"
  ];

  function textContainsAny(text, keywords) {
    const lower = text.toLowerCase();
    return keywords.some(kw => lower.includes(kw));
  }

  let bannerEl = null;
  for (const sel of BANNER_SELECTORS) {
    try {
      const el = document.querySelector(sel);
      if (el && isVisible(el)) {
        bannerEl = el;
        break;
      }
    } catch { /* bad selector */ }
  }

  if (!bannerEl) {
    const candidates = document.querySelectorAll(
      "div, section, aside, dialog, [role='dialog'], [role='alertdialog']"
    );
    for (const el of candidates) {
      if (!isVisible(el)) continue;
      const txt = (el.textContent || "").trim();
      if (txt.length > 20 && txt.length < 4000 && textContainsAny(txt, BANNER_KEYWORDS)) {
        bannerEl = el;
        break;
      }
    }
  }

  if (!bannerEl) {
    const pageText = (document.body.textContent || "").toLowerCase();
    const hasWithdrawal = WITHDRAWAL_KEYWORDS.some(kw => pageText.includes(kw));

    return {
      found: false,
      hasRejectOption: false,
      hasPreChecked: false,
      hasWithdrawal,
      bannerText: ""
    };
  }

  const bannerText = (bannerEl.textContent || "").trim();

  const bannerButtons = Array.from(bannerEl.querySelectorAll("button, a, [role='button']"));
  const hasRejectOption = bannerButtons.some(btn =>
    textContainsAny(btn.textContent || "", REJECT_KEYWORDS)
  );

  const checkboxes = Array.from(bannerEl.querySelectorAll("input[type='checkbox'], input[type='radio']"));
  const NON_ESSENTIAL_PATTERNS = ["analytic", "marketing", "advertising", "social", "performan", "reklam", "pazarlama"];
  const hasPreChecked = checkboxes.some(cb => {
    if (!cb.checked) return false;
    const label = [cb.name, cb.id, cb.getAttribute("aria-label"), cb.closest("label")?.textContent]
      .join(" ").toLowerCase();
    return NON_ESSENTIAL_PATTERNS.some(p => label.includes(p));
  });

  const allInteractives = Array.from(document.querySelectorAll("button, a, [role='button']"));
  const hasWithdrawal = allInteractives.some(el =>
    textContainsAny(el.textContent || "", WITHDRAWAL_KEYWORDS) ||
    textContainsAny(el.getAttribute("title") || "", WITHDRAWAL_KEYWORDS) ||
    textContainsAny(el.getAttribute("aria-label") || "", WITHDRAWAL_KEYWORDS)
  );

  return { found: true, hasRejectOption, hasPreChecked, hasWithdrawal, bannerText };
}

// ─── S1 / S2 / S3 — Third-party scripts & resources ─────────────────────────

/**
 * Covers rules S1, S2, S3.
 *
 * Returns:
 *   thirdPartyDomains  {string[]}  Unique list of external hostnames found.
 *   resourceCount      {number}    Total external resources counted.
 *   resources          {Array}     Raw list: { type, url, domain }.
 */
function enumerateScriptsAndResources() {
  const RESOURCE_SELECTORS = [
    { selector: "script[src]",               attr: "src",  type: "script" },
    { selector: "link[href][rel='stylesheet']", attr: "href", type: "stylesheet" },
    { selector: "img[src]",                  attr: "src",  type: "image" },
    { selector: "iframe[src]",               attr: "src",  type: "iframe" },
    { selector: "video source[src]",         attr: "src",  type: "video" },
    { selector: "audio source[src]",         attr: "src",  type: "audio" },
    { selector: "link[rel='preconnect']",    attr: "href", type: "preconnect" },
    { selector: "link[rel='dns-prefetch']",  attr: "href", type: "dns-prefetch" }
  ];

  const resources = [];
  const seenUrls = new Set();

  for (const { selector, attr, type } of RESOURCE_SELECTORS) {
    for (const el of document.querySelectorAll(selector)) {
      const rawUrl = el.getAttribute(attr);
      if (!rawUrl || seenUrls.has(rawUrl)) continue;
      seenUrls.add(rawUrl);

      if (!isThirdParty(rawUrl)) continue;

      const domain = hostnameOf(rawUrl);
      if (!domain) continue;

      resources.push({ type, url: rawUrl, domain });
    }
  }

  // ── Performance API second pass ──────────────────────────────────────────
  // Catches dynamically-injected scripts, fetch/XHR calls, beacon requests,
  // and any resource not yet in the DOM at scan time.
  // Uses the same seenUrls Set so DOM-found entries are never duplicated.
  if (window.performance && typeof window.performance.getEntriesByType === "function") {
    const INITIATOR_TYPE_MAP = {
      script:           "script",
      link:             "stylesheet",
      img:              "image",
      iframe:           "iframe",
      video:            "video",
      audio:            "audio",
      fetch:            "fetch",
      xmlhttprequest:   "xhr",
      beacon:           "beacon",
      css:              "css",
    };

    const perfEntries = window.performance.getEntriesByType("resource");
    for (const entry of perfEntries) {
      const rawUrl = entry.name;
      // Skip navigation entries (the page itself) and already-seen URLs
      if (!rawUrl || rawUrl === window.location.href) continue;
      if (seenUrls.has(rawUrl)) continue;
      seenUrls.add(rawUrl);

      if (!isThirdParty(rawUrl)) continue;

      const domain = hostnameOf(rawUrl);
      if (!domain) continue;

      const type = INITIATOR_TYPE_MAP[entry.initiatorType] || "other";
      resources.push({ type, url: rawUrl, domain });
    }
  }

  const thirdPartyDomains = [...new Set(resources.map(r => r.domain))];

  return {
    thirdPartyDomains,
    resourceCount: resources.length,
    resources
  };
}

// ─── Sec1 / Sec2 — HTTPS and mixed content ───────────────────────────────────

/**
 * Covers rules Sec1 and Sec2.
 *
 * Returns:
 *   isHTTPS        {boolean}  Whether the page itself is served over HTTPS.
 *   mixedContent   {Array}    List of { type, url } for HTTP resources on an HTTPS page.
 *   hasMixedContent {boolean} Shorthand flag.
 */
function checkHTTPSandMixedContent() {
  const isHTTPS = window.location.protocol === "https:";
  const mixedContent = [];

  if (isHTTPS) {
    const CHECKS = [
      { selector: "script[src]",                    attr: "src",  type: "script" },
      { selector: "link[href][rel='stylesheet']",   attr: "href", type: "stylesheet" },
      { selector: "img[src]",                       attr: "src",  type: "image" },
      { selector: "iframe[src]",                    attr: "src",  type: "iframe" },
      { selector: "video source[src]",              attr: "src",  type: "video" },
      { selector: "audio source[src]",              attr: "src",  type: "audio" },
      { selector: "form[action]",                   attr: "action", type: "form" }
    ];

    for (const { selector, attr, type } of CHECKS) {
      for (const el of document.querySelectorAll(selector)) {
        const val = el.getAttribute(attr);
        if (val && val.trimStart().startsWith("http://")) {
          mixedContent.push({ type, url: val });
        }
      }
    }
  }

  return {
    isHTTPS,
    hasMixedContent: mixedContent.length > 0,
    mixedContent
  };
}

// ─── F1 / F2 / F3 / F4 — Forms and PII fields ────────────────────────────────

/**
 * Covers rules F1, F2, F3, F4.
 */
function detectFormsAndPII() {
  const PII_PATTERNS = [
    { pattern: /\b(e[-_]?mail|e-posta|eposta)\b/i,                   label: "email" },
    { pattern: /\b(first[-_]?name|fname|given[-_]?name|ad|isim)\b/i, label: "first name" },
    { pattern: /\b(last[-_]?name|lname|surname|soyad|soyisim)\b/i,  label: "last name" },
    { pattern: /\b(full[-_]?name|name|ad[-_]?soyad)\b/i,            label: "full name" },
    { pattern: /\b(phone|tel|mobile|cep|gsm|telefon)\b/i,           label: "phone" },
    { pattern: /\b(address|adres|sokak|street|city|şehir|zip|posta[-_]?kodu)\b/i, label: "address" },
    { pattern: /\b(birth[-_]?date|dob|doğum|birthday)\b/i,          label: "birth date" },
    { pattern: /\b(tc|tckn|t\.c\.|kimlik|national[-_]?id|ssn|id[-_]?number)\b/i, label: "national ID" },
    { pattern: /\b(password|parola|şifre|passwd)\b/i,                label: "password" },
    { pattern: /\b(gender|cinsiyet|sex)\b/i,                         label: "gender" },
    { pattern: /\b(credit[-_]?card|card[-_]?number|cvv|ccv)\b/i,   label: "payment" }
  ];

  function extractFieldHints(input) {
    return [
      input.getAttribute("name") || "",
      input.getAttribute("id") || "",
      input.getAttribute("placeholder") || "",
      input.getAttribute("aria-label") || "",
      input.getAttribute("autocomplete") || "",
      (() => {
        const id = input.getAttribute("id");
        if (id) {
          const lbl = document.querySelector(`label[for="${CSS.escape(id)}"]`);
          return lbl ? lbl.textContent : "";
        }
        return input.closest("label")?.textContent || "";
      })()
    ].join(" ");
  }

  const formElements = Array.from(document.querySelectorAll("form"));
  const piiFields = [];
  const thirdPartyActions = [];
  const insecureForms = [];
  const formSummaries = [];

  const allInputs = Array.from(
    document.querySelectorAll("input:not([type='hidden']), textarea, select")
  );

  const seenPIIFields = new Set();

  function checkInputForPII(input) {
    const hints = extractFieldHints(input);
    for (const { pattern, label } of PII_PATTERNS) {
      if (pattern.test(hints)) {
        const key = label + "|" + (input.getAttribute("name") || input.getAttribute("id") || "");
        if (!seenPIIFields.has(key)) {
          seenPIIFields.add(key);
          piiFields.push({
            fieldName: input.getAttribute("name") || input.getAttribute("id") || "(unnamed)",
            fieldType: input.getAttribute("type") || input.tagName.toLowerCase(),
            matchedPattern: label
          });
        }
        break;
      }
    }
  }

  for (const form of formElements) {
    const action = form.getAttribute("action") || "";
    const method = (form.getAttribute("method") || "get").toUpperCase();
    const inputs = Array.from(form.querySelectorAll("input, textarea, select"));

    for (const input of inputs) {
      checkInputForPII(input);
      seenPIIFields.add(
        "checked|" + (input.getAttribute("name") || input.getAttribute("id") || "")
      );
    }

    const resolvedAction = action
      ? new URL(action, window.location.href).href
      : window.location.href;

    const isThirdPartyAction = isThirdParty(resolvedAction);
    if (isThirdPartyAction) {
      thirdPartyActions.push({ action: resolvedAction, domain: hostnameOf(resolvedAction) });
    }

    const actionIsHTTP =
      resolvedAction.startsWith("http://") && !resolvedAction.startsWith("https://");
    const pageIsHTTP = window.location.protocol === "http:";
    const isInsecure = actionIsHTTP || pageIsHTTP;
    if (isInsecure) {
      insecureForms.push({
        action: resolvedAction,
        reason: actionIsHTTP ? "action URL is HTTP" : "page loaded over HTTP"
      });
    }

    formSummaries.push({
      action: resolvedAction,
      method,
      inputCount: inputs.length,
      isThirdPartyAction,
      isInsecure
    });
  }

  for (const input of allInputs) {
    const inForm = !!input.closest("form");
    if (!inForm) checkInputForPII(input);
  }

  return {
    formCount: formElements.length,
    hasForms: formElements.length > 0,
    hasPIIFields: piiFields.length > 0,
    piiFields,
    thirdPartyActions,
    insecureForms,
    forms: formSummaries
  };
}

// ─── P3 — Child-directed content heuristic ───────────────────────────────────

/**
 * Covers rule P3.
 *
 * Scans the page for signals that it may be targeting children. Under GDPR
 * Art.8 and COPPA, child-directed sites face stricter rules around consent and
 * profiling — so the mere presence of trackers on such a site is a red flag.
 *
 * Detection strategy (layered confidence):
 *   HIGH confidence signals (any one of these is sufficient):
 *     - <meta name="audience"> contains "child" / "kids"
 *     - URL hostname contains "kids", "children", "junior", "cocuk" etc.
 *     - Page title or <h1> contains child-directed keywords AND a toy/game term
 *   LOW confidence signals (need 2+ to reach "low" confidence):
 *     - Body text contains child-directed keywords
 *     - Images with child-related alt text
 *     - Age-gate or parental consent form detected
 *
 * Returns:
 *   isChildDirected  {boolean}          True when confidence is low or high.
 *   confidence       {'none'|'low'|'high'}
 *   signals          {string[]}         Human-readable list of detected signals.
 */
function detectChildContent() {
  // ── Keyword lists ──────────────────────────────────────────────────────────

  // Primary child audience keywords (English + Turkish + common EU languages)
  const CHILD_KEYWORDS = [
    // English
    "children", "child", "kids", "kid", "toddler", "infant", "baby",
    "preschool", "kindergarten", "elementary school", "primary school",
    "nursery", "playground",
    // Turkish
    "çocuk", "çocuklar", "bebek", "bebekler", "anaokulu", "ilkokul",
    // German / French / Spanish / Dutch (common EU)
    "kinder", "enfants", "niños", "kinderen"
  ];

  // Secondary topic keywords that raise suspicion when co-occurring with child keywords
  const CHILD_TOPIC_KEYWORDS = [
    "toy", "toys", "oyuncak", "oyuncaklar",
    "game", "games", "oyun", "oyunlar",
    "cartoon", "cartoons", "çizgi film",
    "coloring", "colouring", "boyama",
    "puzzle", "sticker", "stickers",
    "stuffed animal", "plush", "doll", "dolls",
    "lego", "playset", "action figure"
  ];

  // Age-gate signals — forms asking for birth year / parental consent
  const AGE_GATE_PATTERNS = [
    /birth.?year/i, /year.?of.?birth/i, /doğum.?yılı/i,
    /parental.?consent/i, /parent.?permission/i,
    /are you (\d+|over \d+)/i,
    /under (13|16|18)/i, /13 or older/i
  ];

  const signals = [];
  let highConfidence = false;
  let lowConfidenceCount = 0;

  // ── Helper ─────────────────────────────────────────────────────────────────
  function containsAny(text, keywords) {
    const lower = (text || "").toLowerCase();
    return keywords.filter(kw => lower.includes(kw));
  }

  // ── 1. <meta> audience tag (HIGH confidence) ──────────────────────────────
  const audienceMeta = document.querySelector(
    'meta[name="audience"], meta[name="rating"], meta[property="audience"]'
  );
  if (audienceMeta) {
    const content = (audienceMeta.getAttribute("content") || "").toLowerCase();
    if (/child|kid|junior|young/i.test(content)) {
      signals.push(`<meta audience> declares: "${audienceMeta.getAttribute("content")}"`);
      highConfidence = true;
    }
  }

  // ── 2. Hostname keywords (HIGH confidence) ────────────────────────────────
  const hostname = window.location.hostname.toLowerCase();
  const hostMatches = containsAny(hostname, ["kids", "children", "child", "junior",
    "cocuk", "bebek", "kinder", "enfants"]);
  if (hostMatches.length > 0) {
    signals.push(`Hostname contains child-related term: "${hostMatches[0]}"`);
    highConfidence = true;
  }

  // ── 3. Page title (HIGH confidence if title has child keyword + topic keyword) ──
  const title = (document.title || "").toLowerCase();
  const titleChildMatches = containsAny(title, CHILD_KEYWORDS);
  const titleTopicMatches = containsAny(title, CHILD_TOPIC_KEYWORDS);
  if (titleChildMatches.length > 0 && titleTopicMatches.length > 0) {
    signals.push(
      `Page title contains child keyword "${titleChildMatches[0]}" and topic "${titleTopicMatches[0]}"`
    );
    highConfidence = true;
  } else if (titleChildMatches.length > 0) {
    signals.push(`Page title contains: "${titleChildMatches[0]}"`);
    lowConfidenceCount++;
  }

  // ── 4. <h1> / <h2> headings (LOW confidence) ─────────────────────────────
  const headings = Array.from(document.querySelectorAll("h1, h2")).slice(0, 5);
  for (const h of headings) {
    const text = (h.textContent || "").toLowerCase();
    const matches = containsAny(text, CHILD_KEYWORDS);
    if (matches.length > 0) {
      signals.push(`Heading contains: "${h.textContent.trim().slice(0, 60)}"`);
      lowConfidenceCount++;
      break; // one heading signal is enough
    }
  }

  // ── 5. Body text sampling (LOW confidence) ────────────────────────────────
  // Sample visible paragraphs and list items rather than the entire body
  // to avoid false positives from footers/legal text mentioning "children's rights"
  const bodyElements = Array.from(
    document.querySelectorAll("p, li, span, div")
  ).filter(el => {
    if (!isVisible(el)) return false;
    const text = (el.textContent || "").trim();
    return text.length > 30 && text.length < 300;
  }).slice(0, 80); // sample up to 80 short elements

  let bodyChildKeywordCount = 0;
  const seenBodySignals = new Set();
  for (const el of bodyElements) {
    const text = el.textContent || "";
    const childMatches = containsAny(text, CHILD_KEYWORDS);
    const topicMatches = containsAny(text, CHILD_TOPIC_KEYWORDS);
    if (childMatches.length > 0 && !seenBodySignals.has(childMatches[0])) {
      seenBodySignals.add(childMatches[0]);
      bodyChildKeywordCount++;
    }
    // A child keyword + topic keyword co-occurring in body is a stronger signal
    if (childMatches.length > 0 && topicMatches.length > 0 && !highConfidence) {
      signals.push(`Body text: "${childMatches[0]}" + "${topicMatches[0]}"`);
      lowConfidenceCount += 2; // counts as two low signals
      break;
    }
  }
  if (bodyChildKeywordCount >= 3 && !highConfidence) {
    signals.push(`Body text contains "${bodyChildKeywordCount}" child-related keyword occurrences`);
    lowConfidenceCount++;
  }

  // ── 6. Image alt text (LOW confidence) ───────────────────────────────────
  const images = Array.from(document.querySelectorAll("img[alt]")).slice(0, 50);
  let imageChildCount = 0;
  for (const img of images) {
    const alt = (img.getAttribute("alt") || "").toLowerCase();
    if (containsAny(alt, CHILD_KEYWORDS).length > 0 ||
        containsAny(alt, CHILD_TOPIC_KEYWORDS).length > 0) {
      imageChildCount++;
    }
  }
  if (imageChildCount >= 3) {
    signals.push(`${imageChildCount} image(s) have child-related alt text`);
    lowConfidenceCount++;
  }

  // ── 7. Age-gate / parental consent form (LOW confidence) ──────────────────
  const formText = Array.from(document.querySelectorAll("form label, form legend, form p"))
    .map(el => el.textContent || "").join(" ");
  const inputPlaceholders = Array.from(document.querySelectorAll("input[placeholder]"))
    .map(el => el.getAttribute("placeholder") || "").join(" ");
  const ageGateText = formText + " " + inputPlaceholders;

  for (const re of AGE_GATE_PATTERNS) {
    if (re.test(ageGateText)) {
      signals.push(`Age-gate or parental consent form detected`);
      lowConfidenceCount++;
      break;
    }
  }

  // ── Determine overall confidence ──────────────────────────────────────────
  let confidence;
  if (highConfidence) {
    confidence = "high";
  } else if (lowConfidenceCount >= 2) {
    confidence = "low";
  } else {
    confidence = "none";
  }

  return {
    isChildDirected: confidence !== "none",
    confidence,
    signals
  };
}