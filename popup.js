// popup.js
// Orchestrates: SCAN_PAGE (content) → ANALYZE (background) → render report.

"use strict";

// ─── Rule metadata (titles + categories) ─────────────────────────────────────
// Mirrors rules.json but kept inline to avoid an extra fetch in the popup.

const RULE_META = {
  T1:  { title: "Has a privacy policy",                  category: "transparency" },
  T2:  { title: "Privacy policy is easy to find",        category: "transparency" },
  T3:  { title: "Privacy policy has enough detail",      category: "transparency" },
  K1:  { title: "Cookies found on this page",            category: "cookies" },
  K2:  { title: "Cookies are stored securely",           category: "cookies" },
  K3:  { title: "Cookies don't last too long",           category: "cookies" },
  K4:  { title: "Cookie purposes are clear",             category: "cookies" },
  C1:  { title: "Asks for cookie consent",               category: "consent" },
  C2:  { title: "You can say no to cookies",             category: "consent" },
  C3:  { title: "Nothing pre-ticked for you",            category: "consent" },
  C4:  { title: "You can change your mind later",        category: "consent" },
  S1:  { title: "External resources loaded",             category: "third_party" },
  S2:  { title: "Tracking companies detected",           category: "third_party" },
  S3:  { title: "External services identified",          category: "third_party" },
  F1:  { title: "Forms on this page",                    category: "forms" },
  F2:  { title: "Personal info is handled safely",       category: "forms" },
  F3:  { title: "Forms don't send data elsewhere",       category: "forms" },
  F4:  { title: "Forms use an encrypted connection",     category: "forms" },
  Sec1:{ title: "Page uses a secure connection",         category: "security" },
  Sec2:{ title: "No insecure content mixed in",         category: "security" },
  Sec3:{ title: "Extra security protections enabled",   category: "security" },
  D1:  { title: "Data not sent to other countries",      category: "transfers" },
  D2:  { title: "Policy explains data sharing",          category: "transfers" },
  R1:  { title: "Your rights are explained",             category: "rights" },
  R2:  { title: "Contact info for privacy questions",    category: "rights" },
  R3:  { title: "Responsible company is named",          category: "rights" },
  P1:  { title: "Not building a profile on you",         category: "risk" },
  P2:  { title: "No targeted ad companies",              category: "risk" },
  P3:  { title: "Safe for children",                     category: "risk" },
};

const CATEGORY_META = {
  transparency: { label: "Transparency",  icon: "◈" },
  consent:      { label: "Consent",       icon: "◎" },
  cookies:      { label: "Cookies",       icon: "◉" },
  third_party:  { label: "3rd Parties",   icon: "⬡" },
  forms:        { label: "Forms & PII",   icon: "▣" },
  security:     { label: "Security",      icon: "◆" },
  transfers:    { label: "Transfers",     icon: "⇄" },
  rights:       { label: "User Rights",   icon: "◐" },
  risk:         { label: "Risk",          icon: "⚠" },
};

const GRADE_COLOR = { A: "#00e5a0", B: "#6dffb3", C: "#ffb020", D: "#ff7a40", F: "#ff4466" };

const GRADE_TEXT = {
  A: "Strong privacy posture.",
  B: "Good, with minor issues.",
  C: "Moderate compliance gaps.",
  D: "Significant privacy concerns.",
  F: "Poor privacy compliance.",
};

// ─── DOM refs ─────────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

const elScanBtn    = $("scanButton");
const elStatus     = $("status");
const elError      = $("error-msg");
const elResults    = $("results");
const elHero       = $("score-hero");
const elPlaceholder= $("placeholder");
const elGradeLetter= $("grade-letter");
const elGradeScore = $("grade-score");
const elScoreHL    = $("score-headline");
const elScoreSub   = $("score-sub");
const elCatPills   = $("category-pills");
const elRingFill   = $("ring-fill");
const elHttpsBadge = $("https-badge");
const elSiteDomain = $("site-domain");

// ─── Entry point ──────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  // Show current tab domain immediately
  try {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      const u = new URL(tab.url);
      elSiteDomain.textContent = u.hostname;
    }
  } catch { /* ignore */ }

  elScanBtn.addEventListener("click", runScan);
});

// ─── Main scan flow ───────────────────────────────────────────────────────────

async function runScan() {
  elScanBtn.disabled = true;
  elError.style.display = "none";
  elResults.style.display = "none";
  elHero.style.display = "none";
  elPlaceholder.style.display = "none";
  setStatus("Scanning page", true);

  let rawData, tabId, tab;

  try {
    [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    tabId = tab.id;

    // Step 1: get detection data from content script
    rawData = await browser.tabs.sendMessage(tabId, { type: "SCAN_PAGE" });
    if (!rawData) throw new Error("No response from content script. Try refreshing the page.");

  } catch (err) {
    showError("Content script error: " + err.message);
    return;
  }

  setStatus("Analysing trackers & policy", true);

  let analysis;
  try {
    // Step 2: send raw data to background for deep analysis
    analysis = await browser.runtime.sendMessage({
      type: "ANALYZE",
      rawData,
      tabId,
      hostname: new URL(tab.url).hostname
    });
    if (!analysis) throw new Error("No analysis returned from background.");
  } catch (err) {
    showError("Analysis error: " + err.message);
    return;
  }

  setStatus("");
  renderReport(rawData, analysis);
  elScanBtn.disabled = false;
  elScanBtn.textContent = "⬡  Re-scan";
}

// ─── Rendering ────────────────────────────────────────────────────────────────

function renderReport(rawData, analysis) {
  const { ruleResults, totalScore, grade, trackerData } = analysis;

  // ── Header: HTTPS badge ──
  if (rawData.security.isHTTPS) {
    elHttpsBadge.textContent = "HTTPS";
    elHttpsBadge.className = "secure";
  } else if (rawData.security.isHTTPS === false) {
    elHttpsBadge.textContent = "HTTP";
    elHttpsBadge.className = "insecure";
  }

  // ── Score ring ──
  const R = 34;
  const CIRC = 2 * Math.PI * R;
  const gradeColor = GRADE_COLOR[grade] || "#5a6175";

  elRingFill.setAttribute("stroke", gradeColor);
  elRingFill.setAttribute("stroke-dasharray", CIRC.toFixed(2));
  // Start fully empty, animate to final value
  elRingFill.setAttribute("stroke-dashoffset", CIRC.toFixed(2));

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      const offset = CIRC * (1 - totalScore / 100);
      elRingFill.setAttribute("stroke-dashoffset", offset.toFixed(2));
    });
  });

  elGradeLetter.textContent = grade;
  elGradeLetter.style.color = gradeColor;
  elGradeScore.textContent = totalScore + "/100";
  elScoreHL.textContent = GRADE_TEXT[grade] || "";
  elScoreSub.textContent =
    `${trackerData.matched.length} tracker${trackerData.matched.length !== 1 ? "s" : ""} · ` +
    `${rawData.scripts.thirdPartyDomains.length} 3rd-party domain${rawData.scripts.thirdPartyDomains.length !== 1 ? "s" : ""} · ` +
    `${rawData.forms.formCount} form${rawData.forms.formCount !== 1 ? "s" : ""}`;

  // Category pills (quick summary)
  elCatPills.innerHTML = "";
  const catSummary = buildCategorySummary(ruleResults);
  for (const [cat, { passed, total, weighted }] of Object.entries(catSummary)) {
    const pct = total > 0 ? Math.round((passed / total) * 100) : 100;
    const dot = document.createElement("div");
    dot.className = "cat-pill";
    const color = pct === 100 ? "var(--pass)" : pct >= 50 ? "var(--warn)" : "var(--fail)";
    dot.innerHTML =
      `<span class="dot" style="background:${color}"></span>` +
      `<span>${CATEGORY_META[cat]?.label || cat}</span>`;
    elCatPills.appendChild(dot);
  }

  elHero.style.display = "flex";

  // ── Category sections ──
  elResults.innerHTML = "";

  // Tracker detail block (shown if trackers found)
  if (trackerData.matched.length > 0) {
    elResults.appendChild(buildTrackerDetail(trackerData));
  }

  // One section per category
  for (const [cat, { rules }] of Object.entries(catSummary)) {
    elResults.appendChild(buildCategorySection(cat, rules, ruleResults));
  }

  // Animate all category bars on render, not just on open
  setTimeout(() => {
    document.querySelectorAll(".cat-bar-fill").forEach(fill => {
      fill.style.width = fill.dataset.pct + "%";
    });
  }, 80);

  elResults.style.display = "block";
}

// ─── Build category summary map ───────────────────────────────────────────────

function buildCategorySummary(ruleResults) {
  const map = {};

  // Preserve display order
  const ORDER = ["security","transparency","consent","cookies","third_party","forms","transfers","rights","risk"];

  for (const cat of ORDER) {
    map[cat] = { passed: 0, total: 0, weighted: 0, rules: [] };
  }

  for (const r of ruleResults) {
    const meta = RULE_META[r.id];
    if (!meta) continue;
    const cat = meta.category;
    if (!map[cat]) map[cat] = { passed: 0, total: 0, weighted: 0, rules: [] };
    map[cat].rules.push(r);
    if (r.weight > 0 && !r.skipped) {
      map[cat].total++;
      if (r.pass) map[cat].passed++;
      map[cat].weighted += r.weight;
    }
  }

  // Remove empty categories
  for (const cat of Object.keys(map)) {
    if (map[cat].rules.length === 0) delete map[cat];
  }

  return map;
}

// ─── Build a category accordion section ───────────────────────────────────────

function buildCategorySection(cat, rules, allResults) {
  const section = document.createElement("div");
  section.className = "cat-section";

  const catInfo = CATEGORY_META[cat] || { label: cat, icon: "○" };
  const passCount = rules.filter(r => r.weight > 0 && !r.skipped && r.pass).length;
  const totalCount = rules.filter(r => r.weight > 0 && !r.skipped).length;
  const pct = totalCount > 0 ? (passCount / totalCount) * 100 : 100;
  const barColor =
    pct === 100 ? "var(--pass)" :
    pct >= 60   ? "var(--warn)" : "var(--fail)";

  const header = document.createElement("div");
  header.className = "cat-header";
  header.innerHTML = `
    <span class="cat-icon">${catInfo.icon}</span>
    <span class="cat-name">${catInfo.label}</span>
    <div class="cat-bar-wrap">
      <div class="cat-bar-fill" style="width:0%;background:${barColor}" data-pct="${pct.toFixed(0)}"></div>
    </div>
    <span class="cat-fraction">${passCount}/${totalCount}</span>
    <span class="cat-chevron">▾</span>
  `;

  const rulesDiv = document.createElement("div");
  rulesDiv.className = "cat-rules";

  for (const r of rules) {
    const meta = RULE_META[r.id] || { title: r.id };
    const isInfo    = r.weight === 0 && !r.skipped;
    const isSkipped = !!r.skipped;
    const statusClass = isSkipped ? "skip" : isInfo ? "info" : r.pass ? "pass" : "fail";
    const statusIcon  = isSkipped ? "?" : isInfo ? "–" : r.pass ? "✓" : "✗";

    const row = document.createElement("div");
    row.className = "rule-row";
    row.innerHTML = `
      <span class="rule-status ${statusClass}">${statusIcon}</span>
      <div class="rule-text">
        <div class="rule-title">${meta.title}</div>
        <div class="rule-detail">${escHtml(r.detail || "")}</div>
      </div>
      <span class="rule-id">${r.id}</span>
    `;
    rulesDiv.appendChild(row);
  }

  section.appendChild(header);
  section.appendChild(rulesDiv);

  // Toggle open/close
  header.addEventListener("click", () => {
    section.classList.toggle("open");
    // Animate bar on first open
    if (section.classList.contains("open")) {
      const fill = header.querySelector(".cat-bar-fill");
      requestAnimationFrame(() => {
        fill.style.width = fill.dataset.pct + "%";
      });
    }
  });

  // Auto-open failing categories
  if (pct < 100) {
    section.classList.add("open");
    // Animate bar after a brief delay
    setTimeout(() => {
      const fill = header.querySelector(".cat-bar-fill");
      if (fill) fill.style.width = fill.dataset.pct + "%";
    }, 80);
  }

  return section;
}

// ─── Build tracker detail block ───────────────────────────────────────────────

function buildTrackerDetail(trackerData) {
  const wrap = document.createElement("div");
  wrap.id = "tracker-detail";
  wrap.className = "visible";

  const header = document.createElement("div");
  header.className = "tracker-header";
  header.textContent = `Detected Trackers (${trackerData.matched.length})`;
  wrap.appendChild(header);

  const list = document.createElement("div");
  list.className = "tracker-list";

  // Sort: fingerprinting → advertising → social → analytics → rest
  const SORT_ORDER = ["fingerprinting","advertising","social","analytics","crm","cmp","payment","utility","cdn"];
  const sorted = [...trackerData.matched].sort((a, b) => {
    const ai = SORT_ORDER.indexOf(a.category);
    const bi = SORT_ORDER.indexOf(b.category);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });

  for (const t of sorted) {
    const item = document.createElement("div");
    item.className = "tracker-item";
    item.innerHTML = `
      <span class="tracker-name">${escHtml(t.name)}</span>
      <span class="tracker-cat ${t.category}">${t.category}</span>
      ${t.jurisdiction ? `<span class="tracker-jur">${t.jurisdiction}</span>` : ""}
    `;
    list.appendChild(item);
  }

  wrap.appendChild(list);
  return wrap;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function setStatus(text, animateDots = false) {
  if (!text) { elStatus.innerHTML = ""; return; }
  if (animateDots) {
    elStatus.innerHTML =
      escHtml(text) +
      `<span class="scanning-dot">.</span>` +
      `<span class="scanning-dot">.</span>` +
      `<span class="scanning-dot">.</span>`;
  } else {
    elStatus.textContent = text;
  }
}

function showError(msg) {
  setStatus("");
  elError.textContent = msg;
  elError.style.display = "block";
  elPlaceholder.style.display = "none";
  elScanBtn.disabled = false;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}