/**
 * Phishing Threat Intelligence Data & Reference Lists
 */
const THREAT_DATA = {
    urlShorteners: [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "bl.ink", "short.io", "rebrand.ly", "cutt.ly",
        "shorturl.at", "tiny.cc", "rb.gy"
    ],

    suspiciousKeywords: [
        "login", "signin", "verify", "secure", "account", "update",
        "banking", "confirm", "validation", "authenticate", "credential",
        "password", "reset", "support", "helpdesk", "alert", "urgent",
        "suspended", "limited", "unlock", "recover", "webscr", "cmd=",
        "dispatch=", "checkout", "wallet", "paypal", "ebay", "amazon",
        "microsoft", "apple", "google", "facebook", "instagram", "netflix"
    ],

    targetedBrands: [
        "paypal", "apple", "microsoft", "google", "amazon", "facebook",
        "instagram", "netflix", "ebay", "chase", "wellsfargo", "bankofamerica",
        "citibank", "dropbox", "linkedin", "twitter", "whatsapp", "steam",
        "roblox", "coinbase", "binance", "metamask"
    ],

    highRiskTLDs: {
        "xyz": 0.90, "click": 0.88, "loan": 0.87, "work": 0.85,
        "date": 0.84, "review": 0.83, "country": 0.82, "stream": 0.81,
        "gq": 0.80, "ml": 0.80, "cf": 0.79, "tk": 0.79, "ga": 0.78,
        "top": 0.75, "info": 0.68, "biz": 0.60, "online": 0.55,
        "site": 0.52, "website": 0.50, "store": 0.47, "tech": 0.44
    },

    trustedTLDs: [
        "com", "org", "net", "edu", "gov", "mil", "int",
        "co.uk", "ac.uk", "gov.uk", "co.in", "ac.in", "gov.in",
        "de", "fr", "jp", "au", "ca", "ch", "nl", "se", "no", "dk"
    ],

    knownLegitDomains: [
        "google.com", "github.com", "bankofamerica.com", "apple.com",
        "microsoft.com", "amazon.com", "youtube.com", "wikipedia.org",
        "stackoverflow.com", "linkedin.com", "twitter.com", "facebook.com",
        "instagram.com", "reddit.com", "netflix.com", "spotify.com"
    ],

    presets: [
        { label: "— Select a test URL —", url: "" },
        { label: "✅ Legitimate – Google Search", url: "https://www.google.com/search?q=phishing+detection" },
        { label: "✅ Legitimate – GitHub Repository", url: "https://github.com/microsoft/vscode" },
        { label: "✅ Legitimate – Wikipedia Article", url: "https://en.wikipedia.org/wiki/Phishing" },
        { label: "⚠️ Suspicious – URL Shortener Redirect", url: "https://bit.ly/3xHackMe" },
        { label: "🚨 Phishing – PayPal Login Spoof", url: "http://paypal-secure-verify.xyz/login/account/confirm" },
        { label: "🚨 Phishing – Apple ID Brand Spoof", url: "http://apple-id-suspended.click/verify/id?cmd=login" },
        { label: "🚨 Phishing – IP Address Host", url: "http://192.168.1.254/secure/banking/login.php" },
        { label: "🚨 Phishing – Microsoft Credential Harvest", url: "https://microsoft-account-verify.info/signin/recover/password" },
        { label: "🚨 Phishing – Amazon Wallet Phish", url: "http://amazon-wallet-alert.top/update/billing?session=x8K2" }
    ]
};

module.exports = THREAT_DATA;
