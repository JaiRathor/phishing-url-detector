/**
 * Heuristic & Lexical Feature Extraction Module for Phishing Detection
 */
const THREAT_DATA = require('./threatData');

/**
 * Calculates Shannon Entropy of a string (measure of randomness)
 */
function calculateEntropy(str) {
    if (!str) return 0;
    const len = str.length;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    let entropy = 0;
    for (const ch in freq) {
        const p = freq[ch] / len;
        entropy -= p * Math.log2(p);
    }
    return parseFloat(entropy.toFixed(3));
}

/**
 * Safely parses raw URL string into structured components
 */
function parseURL(inputUrl) {
    let raw = (inputUrl || "").trim();
    if (!raw) {
        return { valid: false, error: "URL input cannot be empty." };
    }
    if (!raw.match(/^[a-zA-Z]+:\/\//)) raw = "http://" + raw;
    try {
        const p = new URL(raw);
        return {
            valid: true,
            raw: inputUrl,
            fullUrl: p.href,
            protocol: p.protocol.replace(":", ""),
            hostname: p.hostname,
            pathname: p.pathname,
            search: p.search,
            hash: p.hash,
            port: p.port
        };
    } catch (e) {
        return { valid: false, raw: inputUrl, error: "Invalid URL syntax. Please enter a valid web URL (e.g., https://example.com)" };
    }
}

/**
 * Simulates WHOIS and domain registration metadata
 */
function simulateDomainMetadata(hostname, tld, brandSpoofed, usesIpAddress, isKnownLegit) {
    if (usesIpAddress) {
        return { ageDays: 0, ageLabel: "Unregistered (Raw IP)", whoisPrivacy: false, registrar: "N/A (Direct IP Access)", dnssec: false, riskScore: 95 };
    }
    if (isKnownLegit) {
        return { ageDays: 9850, ageLabel: "27+ Years (Established)", whoisPrivacy: true, registrar: "MarkMonitor Inc. / Verified Corporate", dnssec: true, riskScore: 5 };
    }
    if (brandSpoofed || ["xyz", "click", "loan", "gq", "ml", "cf", "tk"].includes(tld)) {
        return { ageDays: 14, ageLabel: "14 Days (Recently Registered)", whoisPrivacy: true, registrar: "NameCheap Inc. / Privacy Protected", dnssec: false, riskScore: 85 };
    }
    return { ageDays: 450, ageLabel: "~1.2 Years", whoisPrivacy: true, registrar: "GoDaddy LLC / Cloudflare Inc.", dnssec: false, riskScore: 35 };
}

/**
 * Simulates SSL Certificate and trust metadata
 */
function simulateSSLMetadata(isHttps, hostname, usesIpAddress, isKnownLegit) {
    if (!isHttps || usesIpAddress) {
        return { hasSSL: false, issuer: "None (Unencrypted HTTP)", validityDays: 0, extendedValidation: false, hstsEnabled: false, status: "CRITICAL: No Encryption" };
    }
    if (isKnownLegit) {
        return { hasSSL: true, issuer: "DigiCert High Assurance EV CA", validityDays: 365, extendedValidation: true, hstsEnabled: true, status: "SECURE: Valid Extended Validation (EV)" };
    }
    return { hasSSL: true, issuer: "Let's Encrypt Authority X3 (Short-Term)", validityDays: 90, extendedValidation: false, hstsEnabled: false, status: "CAUTION: Domain Validated (DV) Only" };
}

/**
 * Simulates Page Content & Behavioral Signals
 */
function simulateContentMarkers(fullUrl, brandSpoofed, matchedKeywords, isKnownLegit) {
    const triggered = !isKnownLegit && (brandSpoofed || matchedKeywords.length >= 2);
    return {
        externalFormSubmission: triggered ? "SUSPICIOUS: Form posts credentials to cross-origin domain" : "CLEAN: All forms target same origin",
        hiddenIframeDetected:   triggered ? "ALERT: Hidden 1px iframe overlay detected"                : "CLEAN: No suspicious iframe tags",
        scriptObfuscation:      triggered ? "HIGH (88/100) — eval() / unescape() heavy usage"         : "LOW (12/100) — Standard readable code"
    };
}

/**
 * Performs full 18-feature extraction and metadata simulation
 */
function extractFeatures(inputUrl) {
    const parsed = parseURL(inputUrl);
    if (!parsed.valid) {
        return { valid: false, error: parsed.error };
    }

    const hostname = parsed.hostname.toLowerCase();
    const fullUrl  = parsed.fullUrl.toLowerCase();
    const pathname = parsed.pathname;

    // Check if domain is in trusted/known legitimate list
    const cleanHost = hostname.replace(/^www\./, "");
    const isKnownLegit = THREAT_DATA.knownLegitDomains.some(d => cleanHost === d || cleanHost.endsWith("." + d));

    // 1. IP Address as Host
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^0x[0-9a-fA-F]+\./;
    const usesIpAddress = ipRegex.test(hostname);

    // 2. URL Length
    const urlLength = fullUrl.length;
    const lengthFeature = isKnownLegit ? -1 : (urlLength > 75 ? 1 : urlLength >= 54 ? 0 : -1);

    // 3. @ Symbol in URL
    const hasAtSymbol = fullUrl.includes("@");

    // 4. Double Slash in Path
    const hasDoubleSlashInPath = pathname.includes("//");

    // 5. Hyphens in Domain
    const hasHyphenInDomain = hostname.includes("-");
    const hyphenCount = (hostname.match(/-/g) || []).length;

    // 6. Subdomain Depth
    const hostParts = cleanHost.split(".");
    const subDomainCount = Math.max(0, hostParts.length - 2);
    const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : "";
    const rootDomain = hostParts.length >= 2 ? hostParts.slice(-2).join(".") : hostname;

    // 7. HTTPS Protocol
    const isHttps = parsed.protocol === "https";

    // 8. Deceptive SSL Keyword in Domain
    const hasHttpsInDomain = !isKnownLegit && (hostname.includes("https") || hostname.includes("ssl") || hostname.includes("secure"));

    // 9. URL Shortener Service Usage
    const isShortener = THREAT_DATA.urlShorteners.some(s => hostname.includes(s));

    // 10. Suspicious Keywords (exclude brand name if part of its legitimate root domain)
    const matchedKeywords = THREAT_DATA.suspiciousKeywords.filter(kw => {
        if (rootDomain.includes(kw)) return false;
        return fullUrl.includes(kw);
    });

    // 11. Brand Spoofing (only check hostname/subdomain, not path)
    const detectedBrands = THREAT_DATA.targetedBrands.filter(b => hostname.includes(b));
    let brandSpoofed = false;
    if (detectedBrands.length > 0 && !isKnownLegit) {
        const brandInRoot = detectedBrands.some(b => rootDomain.includes(b));
        if (!brandInRoot) brandSpoofed = true;
    }

    // 12. TLD Risk Index
    const tldRiskWeight = THREAT_DATA.highRiskTLDs[tld] || 0.15;
    const isTrustedTLD = THREAT_DATA.trustedTLDs.includes(tld);

    // 13. Shannon Entropy
    const entropy = calculateEntropy(fullUrl);

    // 14. Special Character Density
    const specialCharCount = (fullUrl.match(/[\-_\?=&%#@!\*\+\~]/g) || []).length;

    // 15. Non-Standard Port
    const nonStandardPort = parsed.port !== "" && parsed.port !== "80" && parsed.port !== "443";

    // 16. Punycode / IDN Homograph
    const hasPunycode = hostname.includes("xn--");

    // 17. Query Parameter Depth
    const queryParamCount = parsed.search ? parsed.search.split("&").length : 0;

    // 18. Suspicious File Extension in Path
    const suspiciousExt = /\.(exe|php|asp|bat|sh|cgi|pl)$/i.test(pathname);

    // Simulated Metadata
    const domainMetadata = simulateDomainMetadata(hostname, tld, brandSpoofed, usesIpAddress, isKnownLegit);
    const sslMetadata    = simulateSSLMetadata(isHttps, hostname, usesIpAddress, isKnownLegit);
    const contentMarkers = simulateContentMarkers(fullUrl, brandSpoofed, matchedKeywords, isKnownLegit);

    const features = {
        usesIpAddress:       { val: usesIpAddress,       risk: usesIpAddress ? 0.95 : 0,                                             label: "IP Address in Hostname" },
        urlLength:           { val: urlLength,            risk: lengthFeature === 1 ? 0.70 : lengthFeature === 0 ? 0.35 : 0,          label: "URL Character Length" },
        hasAtSymbol:         { val: hasAtSymbol,          risk: hasAtSymbol ? 0.90 : 0,                                               label: "Presence of '@' Symbol" },
        hasDoubleSlashInPath:{ val: hasDoubleSlashInPath, risk: hasDoubleSlashInPath ? 0.85 : 0,                                      label: "Double Slash Redirect in Path" },
        hasHyphenInDomain:   { val: hasHyphenInDomain,   risk: (isKnownLegit ? 0 : (hyphenCount > 2 ? 0.75 : hasHyphenInDomain ? 0.40 : 0)), label: "Prefix/Suffix Hyphens in Domain", count: hyphenCount },
        subDomainCount:      { val: subDomainCount,       risk: (isKnownLegit ? 0 : (subDomainCount > 2 ? 0.80 : subDomainCount > 1 ? 0.45 : 0)), label: "Subdomain Depth Count" },
        isHttps:             { val: isHttps,              risk: !isHttps ? 0.65 : 0,                                                  label: "HTTPS Protocol Security" },
        hasHttpsInDomain:    { val: hasHttpsInDomain,     risk: hasHttpsInDomain ? 0.85 : 0,                                          label: "Deceptive 'HTTPS/SSL' in Hostname" },
        isShortener:         { val: isShortener,          risk: isShortener ? 0.70 : 0,                                               label: "URL Shortener Service Usage" },
        matchedKeywords:     { val: matchedKeywords,      risk: (isKnownLegit ? 0 : Math.min(0.90, matchedKeywords.length * 0.25)),   label: "Suspicious Keywords in URL" },
        brandSpoofed:        { val: detectedBrands,       risk: brandSpoofed ? 0.95 : 0,                                              label: "Targeted Brand Spoofing / Subdomain Masking" },
        tldRisk:             { val: tld,                  risk: (isKnownLegit || isTrustedTLD) ? 0 : tldRiskWeight,                   label: "Top-Level Domain (TLD) Threat Index" },
        entropy:             { val: entropy,              risk: (isKnownLegit ? 0 : (entropy > 4.5 ? 0.75 : entropy > 4.0 ? 0.40 : 0.10)), label: "URL Shannon Entropy" },
        specialCharCount:    { val: specialCharCount,     risk: (isKnownLegit ? 0 : (specialCharCount > 8 ? 0.70 : specialCharCount > 4 ? 0.35 : 0)), label: "Special Character Count" },
        nonStandardPort:     { val: nonStandardPort,      risk: nonStandardPort ? 0.80 : 0,                                           label: "Non-Standard Web Port Usage", port: parsed.port },
        hasPunycode:         { val: hasPunycode,          risk: hasPunycode ? 0.88 : 0,                                               label: "Punycode / IDN Homograph Attack" },
        queryParamCount:     { val: queryParamCount,      risk: (isKnownLegit ? 0 : (queryParamCount > 5 ? 0.60 : queryParamCount > 3 ? 0.30 : 0)), label: "Query Parameter Depth" },
        suspiciousExt:       { val: suspiciousExt,        risk: suspiciousExt ? 0.85 : 0,                                             label: "Suspicious File Extension in Path" }
    };

    return {
        valid: true,
        parsed,
        hostname,
        fullUrl,
        pathname,
        rootDomain,
        tld,
        isKnownLegit,
        features,
        domainMetadata,
        sslMetadata,
        contentMarkers
    };
}

module.exports = {
    parseURL,
    calculateEntropy,
    extractFeatures
};
