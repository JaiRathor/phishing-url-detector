/**
 * Risk Scoring, Classification Model & Threat Reason Evaluator
 */
const THREAT_DATA = require("./threatData");

function evaluateThreat(analysisResult) {
  if (!analysisResult || !analysisResult.valid) {
    return {
      valid: false,
      score: 0,
      riskLevel: "SAFE",
      threatReasons: ["Invalid or empty URL syntax provided."],
    };
  }

  const {
    features,
    hostname,
    domainMetadata,
    sslMetadata,
    contentMarkers,
    isKnownLegit,
  } = analysisResult;

  // 1. Composite Phishing Score Calculation (diminishing-returns weighted sum)
  const riskValues = Object.values(features)
    .map((x) => (x && typeof x.risk === "number" ? x.risk : 0))
    .filter((r) => r > 0)
    .sort((a, b) => b - a);

  let compositeScore = 0;
  if (riskValues.length > 0) {
    compositeScore = riskValues[0];
    for (let i = 1; i < riskValues.length; i++) {
      compositeScore += riskValues[i] * Math.pow(0.5, i);
    }
    compositeScore = Math.min(0.99, compositeScore);
  }

  // Known-safe domain hard-clamp (google.com, github.com, etc.)
  if (isKnownLegit && (!features.brandSpoofed || !features.brandSpoofed.risk)) {
    compositeScore = 0.02; // Hard-clamp safe sites to 2%
  }

  const scorePercent = Math.round(compositeScore * 100);

  // 2. Risk Level Determination
  let riskLevel = "SAFE";
  if (scorePercent >= 65) {
    riskLevel = "PHISHING THREAT";
  } else if (scorePercent >= 25) {
    riskLevel = "SUSPICIOUS";
  } else {
    riskLevel = "SAFE / LEGITIMATE";
  }

  // 3. Detailed Array of Detected Threat Reasons
  const threatReasons = [];

  if (features.usesIpAddress && features.usesIpAddress.val) {
    threatReasons.push("Host uses raw IP address instead of domain name");
  }
  if (features.brandSpoofed && features.brandSpoofed.risk > 0) {
    threatReasons.push(`Targeted brand spoofing detected in domain string`);
  }
  if (features.hasHttpsInDomain && features.hasHttpsInDomain.risk > 0) {
    threatReasons.push(
      "Deceptive 'https' / 'ssl' keyword embedded inside domain name",
    );
  }
  if (features.hasAtSymbol && features.hasAtSymbol.val) {
    threatReasons.push("URL contains '@' symbol to obscure destination host");
  }
  if (features.hasDoubleSlashInPath && features.hasDoubleSlashInPath.val) {
    threatReasons.push("Double slash '//' redirect pattern found in URL path");
  }
  if (features.isShortener && features.isShortener.val) {
    threatReasons.push(
      "URL uses a known URL shortening service (redirect mask)",
    );
  }
  if (
    features.matchedKeywords &&
    features.matchedKeywords.val &&
    features.matchedKeywords.val.length > 0
  ) {
    threatReasons.push(
      `Suspicious keyword(s) detected: ${features.matchedKeywords.val.join(", ")}`,
    );
  }
  if (features.tldRisk && features.tldRisk.risk > 0.5) {
    threatReasons.push(
      `High-risk top-level domain (.${features.tldRisk.val}) associated with malicious sites`,
    );
  }
  if (features.isHttps && !features.isHttps.val) {
    threatReasons.push("Unencrypted HTTP protocol (lacks SSL/TLS encryption)");
  }
  if (features.hasPunycode && features.hasPunycode.val) {
    threatReasons.push(
      "Punycode / IDN homograph spoofing attempt detected (xn--)",
    );
  }
  if (features.hasHyphenInDomain && features.hasHyphenInDomain.risk > 0) {
    threatReasons.push(
      `Domain contains ${features.hasHyphenInDomain.count || 1} hyphen(s) common in typosquatting`,
    );
  }
  if (features.subDomainCount && features.subDomainCount.risk > 0) {
    threatReasons.push(
      `Excessive subdomain nesting depth (${features.subDomainCount.val} levels)`,
    );
  }
  if (features.urlLength && features.urlLength.risk > 0) {
    threatReasons.push(
      `Suspiciously long URL (${features.urlLength.val} characters)`,
    );
  }
  if (features.entropy && features.entropy.val > 4.2 && !isKnownLegit) {
    threatReasons.push(
      `Elevated Shannon entropy (${features.entropy.val}) indicating randomized URL structure`,
    );
  }
  if (features.specialCharCount && features.specialCharCount.risk > 0) {
    threatReasons.push(`High special character density in URL string`);
  }
  if (features.nonStandardPort && features.nonStandardPort.val) {
    threatReasons.push(
      `Non-standard web port specified (${features.nonStandardPort.port})`,
    );
  }
  if (features.queryParamCount && features.queryParamCount.risk > 0) {
    threatReasons.push(
      `Deep query parameter depth (${features.queryParamCount.val} parameters)`,
    );
  }
  if (features.suspiciousExt && features.suspiciousExt.val) {
    threatReasons.push("Suspicious file extension in URL path");
  }

  if (threatReasons.length === 0) {
    threatReasons.push(
      "URL passed basic lexical and structural security tests.",
    );
  }

  return {
    valid: true,
    score: scorePercent,
    riskLevel,
    threatReasons,
    features,
  };
}

module.exports = {
  evaluateThreat,
};
