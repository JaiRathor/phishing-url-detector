/**
 * Risk Scoring, Classification Model & Threat Reason Evaluator
 */
const THREAT_DATA = require('./threatData');

function evaluateThreat(analysisResult) {
    if (!analysisResult.valid) {
        return {
            valid: false,
            error: analysisResult.error
        };
    }

    const { features, hostname, domainMetadata, sslMetadata, contentMarkers, isKnownLegit } = analysisResult;

    // 1. Composite Phishing Score Calculation (diminishing-returns weighted sum)
    const riskValues = Object.values(features).map(x => x.risk).filter(r => r > 0).sort((a, b) => b - a);
    let compositeScore = 0;
    if (riskValues.length > 0) {
        compositeScore = riskValues[0];
        for (let i = 1; i < riskValues.length; i++) {
            compositeScore += riskValues[i] * Math.pow(0.5, i);
        }
        compositeScore = Math.min(0.99, compositeScore);
    }

    // Known-safe domain hard-clamp
    const isKnownSafe = isKnownLegit && !features.brandSpoofed.risk;
    if (isKnownSafe) {
        compositeScore = 0.02;
    }

    const scorePercent = Math.round(compositeScore * 100);

    // 2. Risk Level Determination
    let riskLevel = "SAFE";
    if (scorePercent >= 65) {
        riskLevel = "PHISHING";
    } else if (scorePercent >= 25) {
        riskLevel = "SUSPICIOUS";
    }

    // 3. Classification Model Confidence (Softmax style)
    const logitSafe   = Math.max(0, 1 - compositeScore * 1.8);
    const logitWarn   = Math.max(0, 1 - Math.abs(compositeScore - 0.42) * 3);
    const logitDanger = Math.pow(compositeScore, 0.8);
    const logitSum    = logitSafe + logitWarn + logitDanger || 1;

    const confSafe   = Math.round((logitSafe   / logitSum) * 100);
    const confWarn   = Math.round((logitWarn   / logitSum) * 100);
    const confDanger = Math.round((logitDanger / logitSum) * 100);

    const predictedClass = confSafe >= confWarn && confSafe >= confDanger
        ? "✅ Legitimate"
        : confWarn >= confDanger
            ? "⚠️ Suspicious"
            : "🚨 Phishing";

    // 4. Array of Detected Threat Reasons
    const threatReasons = [];

    if (features.usesIpAddress.risk > 0) {
        threatReasons.push("Host uses raw IP address instead of domain name");
    }
    if (features.brandSpoofed.risk > 0 && features.brandSpoofed.val.length > 0) {
        threatReasons.push(`Targeted brand spoofing detected for brand(s): ${features.brandSpoofed.val.join(", ")}`);
    }
    if (features.hasHttpsInDomain.risk > 0) {
        threatReasons.push("Deceptive 'https' / 'ssl' keyword embedded inside domain name");
    }
    if (features.hasAtSymbol.risk > 0) {
        threatReasons.push("URL contains '@' symbol to obscure destination host");
    }
    if (features.hasDoubleSlashInPath.risk > 0) {
        threatReasons.push("Double slash '//' redirect pattern found in URL path");
    }
    if (features.isShortener.risk > 0) {
        threatReasons.push("URL uses a known URL shortening service (redirect mask)");
    }
    if (features.matchedKeywords.risk > 0 && features.matchedKeywords.val.length > 0) {
        threatReasons.push(`Suspicious keyword(s) detected: ${features.matchedKeywords.val.join(", ")}`);
    }
    if (features.tldRisk.risk > 0.5) {
        threatReasons.push(`High-risk top-level domain (.${features.tldRisk.val}) associated with malicious sites`);
    }
    if (features.isHttps.risk > 0) {
        threatReasons.push("Unencrypted HTTP protocol (lacks SSL/TLS encryption)");
    }
    if (features.hasPunycode.risk > 0) {
        threatReasons.push("Punycode / IDN homograph spoofing attempt detected (xn--)");
    }
    if (features.hasHyphenInDomain.risk > 0) {
        threatReasons.push(`Domain contains ${features.hasHyphenInDomain.count || 1} hyphen(s) common in typosquatting`);
    }
    if (features.subDomainCount.risk > 0) {
        threatReasons.push(`Excessive subdomain nesting depth (${features.subDomainCount.val} levels)`);
    }
    if (features.urlLength.risk > 0) {
        threatReasons.push(`Suspiciously long URL (${features.urlLength.val} characters)`);
    }
    if (features.entropy.risk > 0.3) {
        threatReasons.push(`Elevated Shannon entropy (${features.entropy.val}) indicating randomized URL structure`);
    }
    if (features.specialCharCount.risk > 0) {
        threatReasons.push(`High special character density (${features.specialCharCount.val} special characters)`);
    }
    if (features.nonStandardPort.risk > 0) {
        threatReasons.push(`Non-standard web port specified (${features.nonStandardPort.port})`);
    }
    if (features.queryParamCount.risk > 0) {
        threatReasons.push(`Deep query parameter depth (${features.queryParamCount.val} parameters)`);
    }
    if (features.suspiciousExt.risk > 0) {
        threatReasons.push("Suspicious file extension in URL path");
    }
    if (!isKnownSafe && domainMetadata.ageDays > 0 && domainMetadata.ageDays <= 30) {
        threatReasons.push(`Recently registered domain (${domainMetadata.ageLabel})`);
    }
    if (contentMarkers.externalFormSubmission.includes("SUSPICIOUS")) {
        threatReasons.push("Form submits sensitive credentials to cross-origin external host");
    }

    if (threatReasons.length === 0) {
        threatReasons.push("No explicit threat indicators detected. URL appears structurally safe.");
    }

    return {
        valid: true,
        riskLevel,
        score: scorePercent,
        threatReasons,
        confidence: {
            safe: confSafe,
            warn: confWarn,
            danger: confDanger
        },
        predictedClass,
        parsed: analysisResult.parsed,
        features: analysisResult.features,
        domainMetadata,
        sslMetadata,
        contentMarkers
    };
}

module.exports = {
    evaluateThreat
};
