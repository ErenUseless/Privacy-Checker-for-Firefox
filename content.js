// content.js

browser.runtime.onMessage.addListener((message, sender) => {
  if (message && message.type === "SCAN_PAGE") {
    const title        = document.title || "(no title)";
    const privacyPolicy = findPrivacyPolicyLink();
    const cookieBanner  = detectCookieBanner();
    const scripts       = enumerateScriptsAndResources();
    const security      = checkHTTPSandMixedContent();
    const forms         = detectFormsAndPII();
    const childContent  = detectChildContent();          

    const detectionResults = {
      title,
      privacyPolicy,
      cookieBanner,
      scripts,
      security,
      forms,
      childContent
    };

    return Promise.resolve(detectionResults);
  }
});